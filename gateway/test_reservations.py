"""Workflow reservation tests; synthetic workers, no desktop acceptance."""
import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from fastmcp import FastMCP, Client
from channel import Channel, ChannelDenied, WorkflowBusy, EXPOSED_TOOLS
from registry import Registry
from gateway import ReachProvider
from test_registry import Fixture
from test_gateway import catalog


class ReservationLifecycle(unittest.TestCase):
    def setUp(self):
        self.f=Fixture(count=2)
        self.r=self.f.registry
        self.vm='vm-fixture-1'
        self.w=self.f.workers[self.vm]
    def tearDown(self):
        self.f.close()

    def test_claim_requires_desktop_lease_and_never_grants_one(self):
        with self.assertRaises(ChannelDenied):
            self.r.claim(self.vm,'42')
        self.assertIsNone(self.r.lease_public(self.vm))
        self.f.lease(self.vm,30)
        claim=self.r.claim(self.vm,'42')
        self.assertTrue(claim['claimed'])
        self.assertEqual(self.f.clock.now+30,claim['expires_at'])
        self.assertEqual('preparing',claim['phase'])
        with self.assertRaises(WorkflowBusy):
            self.r.authorize_reservation(self.vm,'42',self.f.channel.epoch,claim['workflow_token'])
        # Release/renew may inspect the authenticated generation while its
        # native worker is preparing; desktop dispatch still uses ready=True.
        _, pending=self.r.authorize_reservation(self.vm,'42',self.f.channel.epoch,claim['workflow_token'],ready=False)
        self.assertEqual(self.r.control_public(self.vm)['control_id'],pending['control_id'])
        desired=self.r.control_public(self.vm)
        self.w['poll']['control_id']=desired['control_id']
        self.f.channel.worker_heartbeat(self.w['auth'],self.w['poll'])
        self.assertEqual('ready',self.r.reservation_status(self.vm,'42')['phase'])

    def test_expiry_requires_idle_ack_and_never_resurrects(self):
        self.f.lease(self.vm,120)
        claim=self.f.claim(self.vm,10)
        token=claim['workflow_token']
        old=self.w['poll']['control_id']
        self.f.clock.now+=10
        busy=self.r.claim(self.vm,'42')
        self.assertFalse(busy['claimed'])
        self.assertEqual('draining',busy['phase'])
        self.assertIsNone(self.f.channel.worker_heartbeat(self.w['auth'],self.w['poll'])['control'])
        with self.assertRaises(ChannelDenied):
            self.r.renew_claim(self.vm,'42',token)
        self.w['poll']['control_id']=None
        self.f.channel.worker_heartbeat(self.w['auth'],self.w['poll'])
        new=self.r.claim(self.vm,'42',20)
        self.assertTrue(new['claimed'])
        self.assertNotEqual(token,new['workflow_token'])
        self.assertNotEqual(old,self.r.control_public(self.vm)['control_id'])

    def test_renew_is_explicit_and_capped_by_existing_lease(self):
        lease=self.f.lease(self.vm,100)
        claim=self.f.claim(self.vm,20)
        self.f.clock.now+=5
        self.r.authorize_reservation(self.vm,'42',self.f.channel.epoch,claim['workflow_token'])
        self.assertEqual(claim['expires_at'],self.r.control_public(self.vm)['expires_at'])
        renewed=self.r.renew_claim(self.vm,'42',claim['workflow_token'],600)
        self.assertEqual(lease['expires_at'],renewed['expires_at'])
        self.assertNotIn('workflow_token',renewed)
        for ttl in (0,601,True,1.5):
            with self.assertRaises(ChannelDenied):
                self.r.renew_claim(self.vm,'42',claim['workflow_token'],ttl)

    def test_secret_only_issued_once_and_foreign_capabilities_denied(self):
        self.f.lease(self.vm)
        claim=self.f.claim(self.vm)
        token=claim['workflow_token']
        for value in (self.r.list_vms('42'),self.r.claim(self.vm,'42'),
                      self.r.control_public(self.vm),self.r.owner_connection(self.vm),
                      '\n'.join(self.r.db.iterdump())):
            self.assertNotIn(token,str(value))
        self.f.lease('vm-fixture-2')
        for vm,subject,secret in ((self.vm,'43',token),('vm-fixture-2','42',token),(self.vm,'42','a'*43)):
            with self.assertRaises(ChannelDenied):
                self.r.authorize_reservation(vm,subject,self.f.channel.epoch,secret)
        self.r.release_claim(self.vm,'42',token)
        with self.assertRaises(ChannelDenied):
            self.r.release_claim(self.vm,'42',token)

    def test_missing_worker_protocol_and_stale_ack_fail_closed(self):
        hello=dict(self.w['hello']);del hello['control_protocol']
        with self.assertRaises(ChannelDenied):
            self.f.channel.worker_connect(self.w['auth'],hello)
        self.f.lease(self.vm)
        self.f.claim(self.vm)
        for patcher in ({'control_id':'f'*32},{'connection_id':'f'*32,'control_id':None},
                        {'gateway_epoch':'f'*32,'control_id':None}):
            with self.assertRaises(ChannelDenied):
                self.f.channel.worker_heartbeat(self.w['auth'],{**self.w['poll'],**patcher})
        self.assertEqual('ready',self.r.reservation_status(self.vm,'42')['phase'])

    def test_old_same_worker_reconnect_cannot_revive_offline_claim(self):
        self.f.lease(self.vm,120)
        claim=self.f.claim(self.vm,120)
        self.f.clock.now+=46
        result=self.f.channel.worker_connect(self.w['auth'],self.w['hello'])
        self.assertIsNone(result['control'])
        with self.assertRaises(ChannelDenied):
            self.r.renew_claim(self.vm,'42',claim['workflow_token'])

    def test_old_database_columns_upgrade_without_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'old.sqlite3'
            db=sqlite3.connect(path)
            db.executescript("""
              CREATE TABLE connections(vm_id TEXT PRIMARY KEY,instance_id TEXT NOT NULL,session_id TEXT NOT NULL,
                connection_id TEXT NOT NULL,gateway_epoch TEXT NOT NULL,last_seen REAL NOT NULL,desktop_state TEXT NOT NULL);
              CREATE TABLE jobs(job_id TEXT PRIMARY KEY,vm_id TEXT NOT NULL,lease_id TEXT NOT NULL,
                gateway_epoch TEXT NOT NULL,state TEXT NOT NULL,created_at INTEGER NOT NULL,deadline INTEGER NOT NULL,tool TEXT NOT NULL);
            """)
            db.close()
            registry=Registry(path,self.f.clock)
            try:
                for table in ('connections','jobs'):
                    self.assertIn('control_id',{row['name'] for row in registry.db.execute('PRAGMA table_info('+table+')')})
                channel=Channel(registry)
                self.assertEqual([],channel.discovery('42'))
                self.assertEqual(0,registry.db.execute('SELECT COUNT(*) FROM reservations').fetchone()[0])
            finally:
                registry.close()


class PublicWorkflowRoundtrip(unittest.IsolatedAsyncioTestCase):
    async def test_actual_provider_claim_busy_targeted_read_release_and_new_claim(self):
        f=Fixture(count=2)
        try:
            for vm in f.workers:f.lease(vm)
            server=FastMCP('workflow-fixture',providers=[ReachProvider(f.channel,catalog())])
            with patch('gateway.subject',return_value='42'):
                async with Client(server) as client:
                    one=json.loads((await client.call_tool('reach_claim_vm',{'vm_id':'vm-fixture-1'})).content[0].text)
                    busy=json.loads((await client.call_tool('reach_claim_vm',{'vm_id':'vm-fixture-1'})).content[0].text)
                    two=json.loads((await client.call_tool('reach_claim_vm',{'vm_id':'vm-fixture-2'})).content[0].text)
                    self.assertTrue(one['claimed']);self.assertTrue(two['claimed'])
                    self.assertFalse(busy['claimed']);self.assertNotIn('workflow_token',busy)
                    tasks=[]
                    for vm,claim in (('vm-fixture-1',one),('vm-fixture-2',two)):
                        worker=f.workers[vm]
                        worker['poll']['control_id']=f.registry.control_public(vm)['control_id']
                        f.channel.worker_heartbeat(worker['auth'],worker['poll'])
                        tasks.append(asyncio.create_task(client.call_tool('reach_get_screen_info',
                            {'vm_id':vm,'workflow_token':claim['workflow_token']})))
                    for vm in ('vm-fixture-2','vm-fixture-1'):
                        worker=f.workers[vm]
                        packet=await f.channel.worker_next(worker['auth'],worker['poll'],wait=1)
                        self.assertEqual({},packet['params']['arguments'])
                        self.assertNotIn(one['workflow_token'],json.dumps(packet))
                        self.assertNotIn(two['workflow_token'],json.dumps(packet))
                        f.channel.worker_result(worker['auth'],f.result(packet,vm))
                    results=await asyncio.gather(*tasks)
                    self.assertEqual(['vm-fixture-1','vm-fixture-2'],[r.content[0].text for r in results])
                    released=json.loads((await client.call_tool('reach_release_vm',
                        {'vm_id':'vm-fixture-1','workflow_token':one['workflow_token']})).content[0].text)
                    self.assertEqual('draining',released['phase'])
                    busy=json.loads((await client.call_tool('reach_claim_vm',{'vm_id':'vm-fixture-1'})).content[0].text)
                    self.assertFalse(busy['claimed'])
                    worker=f.workers['vm-fixture-1'];worker['poll']['control_id']=None
                    f.channel.worker_heartbeat(worker['auth'],worker['poll'])
                    fresh=json.loads((await client.call_tool('reach_claim_vm',{'vm_id':'vm-fixture-1'})).content[0].text)
                    self.assertTrue(fresh['claimed'])
                    self.assertNotEqual(one['workflow_token'],fresh['workflow_token'])
        finally:
            f.close()


if __name__=='__main__':
    unittest.main()
