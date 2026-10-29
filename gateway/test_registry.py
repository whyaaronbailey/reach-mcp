"""Synthetic three-identity tests. No desktop acceptance or live credentials."""
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from channel import Channel, ChannelDenied, encoded, loads, validate_request, validate_catalog, catalog_digest
from private_api import PrivateAPI
from registry import Registry, CONNECTION_KEYS, vm_identity


class Clock:
    def __init__(self):
        self.now=2000000000
    def __call__(self):
        return self.now


class Fixture:
    def __init__(self, count=3, subjects=None):
        self.temporary=tempfile.TemporaryDirectory()
        self.path=Path(self.temporary.name)/'registry.sqlite3'
        self.clock=Clock()
        self.registry=Registry(self.path,self.clock)
        self.channel=Channel(self.registry)
        self.workers={}
        for number in range(1,count+1):
            vm_id='vm-fixture-'+str(number)
            identity={'version':2,'vm_id':vm_id,'machine_uuid':f'00000000-0000-0000-0000-{number:012x}',
                'account_sid':f'S-1-5-21-100-200-300-{number+1000}'}
            grant=self.registry.grant(vm_id,'Fixture '+str(number),identity['machine_uuid'],identity['account_sid'],subjects or ['42'])
            enrolled=self.channel.worker_enroll('Bearer '+grant['enrollment_token'],identity)
            authorization='Bearer '+enrolled['worker_token']
            hello={**identity,'instance_id':f'{number:032x}','session_id':'boot-1:logon-1','desktop_state':'ready','control_id':None,'control_protocol':1}
            connection=self.channel.worker_connect(authorization,hello)
            poll={key:hello[key] for key in ('version','vm_id','instance_id','session_id')}
            poll.update({key:connection[key] for key in ('connection_id','gateway_epoch')})
            poll['desktop_state']='ready'
            poll['control_id']=None
            self.workers[vm_id]={'auth':authorization,'hello':hello,'poll':poll,'grant':grant,'identity':identity}
    def lease(self,vm_id,seconds=120):
        return self.registry.authorize_lease(vm_id,'42',seconds)
    def claim(self,vm_id,seconds=120):
        worker=self.workers[vm_id]
        worker['poll']['control_id']=None
        self.channel.worker_heartbeat(worker['auth'],worker['poll'])
        value=self.registry.claim(vm_id,'42',seconds)
        assert value['claimed'], value
        worker['workflow_token']=value['workflow_token']
        worker['poll']['control_id']=self.registry.control_public(vm_id)['control_id']
        self.channel.worker_heartbeat(worker['auth'],worker['poll'])
        return value
    def result(self,packet,text='fixture-result'):
        return {**{key:packet[key] for key in CONNECTION_KEYS|{'lease_id','job_id'}},
            'failed':False,'result':{'content':[{'type':'text','text':text}],'isError':False}}
    def close(self):
        self.registry.close()
        self.temporary.cleanup()


class ActiveProtocolBoundary(unittest.TestCase):
    def test_actual_pinned_catalog_metadata_and_exact_digest(self):
        actual=loads(Path(__file__).with_name('tool-catalog.json').read_bytes())
        self.assertEqual(30,len(validate_catalog(actual)['tools']))
        self.assertEqual('4395d90cdf0987bc9a3e8eca226f47c8c4cca515c8eb6e62ed7313216a86f9ed',catalog_digest(actual))
        self.assertEqual(catalog_digest(actual),catalog_digest({'tools':actual['tools']}))
        for patch in ({'ttlMs':1},{'ttlMs':False},{'cacheScope':'public'},{'resultType':'partial'},{'extra':True}):
            with self.assertRaises(ChannelDenied):
                validate_catalog({**actual,**patch})
        with self.assertRaises(ChannelDenied):
            validate_catalog({key:value for key,value in actual.items() if key!='ttlMs'})
        with self.assertRaises(ChannelDenied):
            validate_catalog({**actual,'tools':actual['tools']+[{'name':'unreviewed','inputSchema':{}}]})

    def test_vm_identity_canonical_length_boundaries(self):
        self.assertEqual('a',vm_identity('a'))
        self.assertEqual('a'*64,vm_identity('a'*64))
        for value in ('','a'*65,'VM-BETA','vm_nexus'):
            with self.assertRaises(ChannelDenied):
                vm_identity(value)

    def test_duplicate_nonfinite_and_oversized_payloads(self):
        for raw in (b'{"version":2,"version":2}',b'{"x":NaN}',b'{"x":Infinity}',b'\xff'):
            with self.assertRaises(ChannelDenied):
                loads(raw)
        with self.assertRaises(ChannelDenied):
            encoded({'text':'x'*262144})
    def test_unknown_tools_and_extra_dispatch_fields(self):
        for params in ({'name':'owner_shell','arguments':{}},
                       {'name':'reach_click','arguments':{},'vm_id':'injected'}):
            with self.assertRaises(ChannelDenied):
                validate_request('tools/call',params)


class RegistryBoundary(unittest.TestCase):
    def setUp(self):
        self.fixture=Fixture()
        self.registry=self.fixture.registry
        self.channel=self.fixture.channel
        self.worker=self.fixture.workers['vm-fixture-1']
    def tearDown(self):
        self.fixture.close()

    def test_enrollment_never_grants_lease(self):
        self.assertTrue(all(not row['desktop_authorized'] for row in self.channel.discovery('42')))
        with self.assertRaises(ChannelDenied):
            self.registry.authorize('vm-fixture-1','42',self.channel.epoch)

    def test_one_use_enrollment_exact_identity(self):
        with self.assertRaises(ChannelDenied):
            self.channel.worker_enroll('Bearer '+self.worker['grant']['enrollment_token'],self.worker['identity'])
        identity=self.worker['identity']
        grant=self.registry.grant(identity['vm_id'],'Fixture',identity['machine_uuid'],identity['account_sid'],['42'])
        wrong={**identity,'account_sid':'S-1-5-21-100-200-300-9999'}
        with self.assertRaises(ChannelDenied):
            self.channel.worker_enroll('Bearer '+grant['enrollment_token'],wrong)
        self.channel.worker_enroll('Bearer '+grant['enrollment_token'],identity)

    def test_wrong_vm_credentials_and_unauthorized_discovery(self):
        worker2=self.fixture.workers['vm-fixture-2']
        with self.assertRaises(ChannelDenied):
            self.channel.worker_connect(self.worker['auth'],worker2['hello'])
        self.assertEqual([],self.channel.discovery('43'))
        with self.assertRaises(ChannelDenied):
            self.registry.authorize_lease('vm-fixture-1','43',30)

    def test_bounded_explicit_lease_expiry(self):
        for seconds in (0,7201,True):
            with self.assertRaises(ChannelDenied):
                self.registry.authorize_lease('vm-fixture-1','42',seconds)
        self.fixture.lease('vm-fixture-1',10)
        self.fixture.clock.now+=10
        with self.assertRaises(ChannelDenied):
            self.registry.authorize('vm-fixture-1','42',self.channel.epoch)
        self.assertFalse(self.channel.discovery('42')[0]['desktop_authorized'])

    def test_duplicate_worker_and_session_fence(self):
        self.fixture.lease('vm-fixture-1')
        duplicate={**self.worker['hello'],'instance_id':'f'*32}
        with self.assertRaises(ChannelDenied):
            self.channel.worker_connect(self.worker['auth'],duplicate)
        with self.assertRaises(ChannelDenied):
            self.channel.worker_connect(self.worker['auth'],{**self.worker['hello'],'session_id':'boot-1:logon-2'})
        self.fixture.clock.now+=46
        value=self.channel.worker_connect(self.worker['auth'],duplicate)
        self.assertIsNone(value['lease'])
        with self.assertRaises(ChannelDenied):
            self.registry.connection(self.worker['auth'],{k:self.worker['poll'][k] for k in CONNECTION_KEYS})

    def test_lock_pause_revoke_independent(self):
        for vm_id in self.fixture.workers:
            self.fixture.lease(vm_id)
        self.registry.connection(self.worker['auth'],{**self.worker['poll'],'desktop_state':'locked'},heartbeat=True)
        with self.assertRaises(ChannelDenied):
            self.fixture.lease('vm-fixture-1')
        self.registry.pause('vm-fixture-2')
        self.assertIsNone(self.registry.lease_public('vm-fixture-2'))
        self.registry.revoke('vm-fixture-1')
        self.assertTrue(self.registry.authorize('vm-fixture-3','42',self.channel.epoch))

    def test_self_revocation_confirmation_is_idempotent_but_not_authentication(self):
        vm_id='vm-fixture-1';body={'version':2,'vm_id':vm_id}
        self.registry.revoke(vm_id)
        for _ in range(2):
            self.assertTrue(self.registry.self_revoke(self.worker['auth'],body)['revoked'])
        with self.assertRaises(ChannelDenied):
            self.registry.authenticate(self.worker['auth'],vm_id)
        with self.assertRaises(ChannelDenied):
            self.registry.self_revoke(self.fixture.workers['vm-fixture-2']['auth'],body)
        identity=self.worker['identity']
        grant=self.registry.grant(vm_id,'Rotated',identity['machine_uuid'],identity['account_sid'],['42'])
        replacement=self.registry.enroll('Bearer '+grant['enrollment_token'],identity)
        with self.assertRaises(ChannelDenied):
            self.registry.self_revoke(self.worker['auth'],body)
        self.assertFalse(self.registry.get(vm_id)['revoked'])
        self.assertTrue(self.registry.authenticate('Bearer '+replacement['worker_token'],vm_id))

    def test_offline_discovery_is_honest(self):
        self.fixture.lease('vm-fixture-1')
        self.fixture.clock.now+=46
        row=self.channel.discovery('42')[0]
        self.assertEqual('offline',row['desktop_state'])
        self.assertFalse(row['desktop_authorized'])
        with self.assertRaises(ChannelDenied):
            self.registry.authorize('vm-fixture-1','42',self.channel.epoch)

    def test_owner_cli_connection_does_not_restart_gateway(self):
        other=Registry(self.fixture.path,self.fixture.clock)
        try:
            self.fixture.lease('vm-fixture-1')
            self.assertEqual(self.channel.epoch,other.epoch())
            other.pause('vm-fixture-1')
            self.assertIsNone(self.registry.lease_public('vm-fixture-1'))
        finally:
            other.close()

    def test_discovery_authority_is_bound_to_requesting_subject(self):
        fixture=Fixture(count=1,subjects=['42','43'])
        try:
            fixture.lease('vm-fixture-1')
            self.assertTrue(fixture.channel.discovery('42')[0]['desktop_authorized'])
            self.assertFalse(fixture.channel.discovery('43')[0]['desktop_authorized'])
            with self.assertRaises(ChannelDenied):
                fixture.registry.authorize('vm-fixture-1','43',fixture.channel.epoch)
        finally:
            fixture.close()

    def test_owner_network_proof_binding_cannot_follow_replacement_connection(self):
        current=self.registry.owner_connection('vm-fixture-1')
        self.assertNotIn('token_hash',current)
        with self.assertRaises(ChannelDenied):
            self.registry.authorize_lease('vm-fixture-1','42',30,
                expected_connection={'connection_id':'e'*32,'gateway_epoch':current['gateway_epoch']})
        self.registry.authorize_lease('vm-fixture-1','42',30,
            expected_connection={key:current[key] for key in ('connection_id','gateway_epoch')})

    def test_heartbeat_observes_revocation_and_session_lock(self):
        lease=self.fixture.lease('vm-fixture-1')
        result=self.channel.worker_heartbeat(self.worker['auth'],self.worker['poll'])
        self.assertEqual(lease['lease_id'],result['lease']['lease_id'])
        self.registry.pause('vm-fixture-1')
        self.assertIsNone(self.channel.worker_heartbeat(self.worker['auth'],self.worker['poll'])['lease'])
        self.fixture.lease('vm-fixture-1')
        result=self.channel.worker_heartbeat(self.worker['auth'],{**self.worker['poll'],'desktop_state':'locked'})
        self.assertEqual('locked',result['desktop_state'])
        self.assertIsNone(result['lease'])

    def test_database_contains_no_bearer_tokens(self):
        dump='\n'.join(self.registry.db.iterdump())
        for worker in self.fixture.workers.values():
            self.assertNotIn(worker['auth'][7:],dump)
            self.assertNotIn(worker['grant']['enrollment_token'],dump)


class RoutingBoundary(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture=Fixture()
        self.channel=self.fixture.channel
        self.registry=self.fixture.registry
        for vm_id in self.fixture.workers:
            self.fixture.lease(vm_id)
            self.fixture.claim(vm_id)
    async def asyncTearDown(self):
        self.fixture.close()

    async def dispatch(self,vm_id,name='reach_get_screen_info',args=None):
        task=asyncio.create_task(self.channel.request(name,args or {},vm_id,'42',self.fixture.workers[vm_id]['workflow_token']))
        worker=self.fixture.workers[vm_id]
        packet=await self.channel.worker_next(worker['auth'],worker['poll'],wait=1)
        return task,packet

    async def test_three_vm_interleaved_targeting(self):
        ids=list(self.fixture.workers)
        tasks=[asyncio.create_task(self.channel.request('reach_get_screen_info',{},vm_id,'42',self.fixture.workers[vm_id]['workflow_token'])) for vm_id in ids]
        packets=await asyncio.gather(*(self.channel.worker_next(self.fixture.workers[vm_id]['auth'],self.fixture.workers[vm_id]['poll'],wait=1) for vm_id in ids))
        for vm_id,packet in reversed(list(zip(ids,packets))):
            self.assertEqual(vm_id,packet['vm_id'])
            self.channel.worker_result(self.fixture.workers[vm_id]['auth'],self.fixture.result(packet,vm_id))
        results=await asyncio.gather(*tasks)
        self.assertEqual(ids,[value['content'][0]['text'] for value in results])

    async def test_wrong_result_credentials_binding_and_replay(self):
        task,packet=await self.dispatch('vm-fixture-1')
        result=self.fixture.result(packet)
        with self.assertRaises(ChannelDenied):
            self.channel.worker_result(self.fixture.workers['vm-fixture-2']['auth'],result)
        for patch in ({'vm_id':'vm-fixture-2'},{'lease_id':'e'*32},{'job_id':'e'*32},{'session_id':'wrong-session'},{'gateway_epoch':'f'*32}):
            with self.assertRaises(ChannelDenied):
                self.channel.worker_result(self.fixture.workers['vm-fixture-1']['auth'],{**result,**patch})
        self.channel.worker_result(self.fixture.workers['vm-fixture-1']['auth'],result)
        with self.assertRaises(ChannelDenied):
            self.channel.worker_result(self.fixture.workers['vm-fixture-1']['auth'],result)
        await task

    async def test_revocation_does_not_block_other_vm(self):
        task1,packet1=await self.dispatch('vm-fixture-1')
        task2,packet2=await self.dispatch('vm-fixture-2')
        owner=Registry(self.fixture.path,self.fixture.clock)
        owner.revoke('vm-fixture-1')
        owner.close()
        self.channel.worker_result(self.fixture.workers['vm-fixture-2']['auth'],self.fixture.result(packet2))
        await task2
        with self.assertRaises(ChannelDenied):
            await asyncio.wait_for(task1,1)
        with self.assertRaises(ChannelDenied):
            self.channel.worker_result(self.fixture.workers['vm-fixture-1']['auth'],self.fixture.result(packet1))

    async def test_canceled_delivered_action_is_uncertain_never_requeued(self):
        task,packet=await self.dispatch('vm-fixture-1','reach_click',{'x':1,'y':1})
        task.cancel()
        with self.assertRaises(ChannelDenied):
            await task
        state=self.registry.db.execute('SELECT state FROM jobs WHERE job_id=?',(packet['job_id'],)).fetchone()[0]
        self.assertEqual('outcome_uncertain',state)
        worker=self.fixture.workers['vm-fixture-1']
        self.assertIsNone(await self.channel.worker_next(worker['auth'],worker['poll'],wait=.01))
        with self.assertRaises(ChannelDenied):
            self.channel.worker_result(worker['auth'],self.fixture.result(packet))

    async def test_gateway_restart_invalidates_lease_and_uncertain_work(self):
        task,packet=await self.dispatch('vm-fixture-1','reach_type_text',{'text':'private-input-fixture'})
        restarted=Channel(self.registry)
        with self.assertRaises(ChannelDenied):
            await asyncio.wait_for(task,1)
        with self.assertRaises(ChannelDenied):
            restarted.worker_result(self.fixture.workers['vm-fixture-1']['auth'],self.fixture.result(packet))
        hello=self.fixture.workers['vm-fixture-1']
        connection=restarted.worker_connect(hello['auth'],hello['hello'])
        self.assertIsNone(connection['lease'])
        with self.assertRaises(ChannelDenied):
            await restarted.request('reach_get_screen_info',{},'vm-fixture-1','42',self.fixture.workers['vm-fixture-1'].get('workflow_token','x'*43))
        dump='\n'.join(self.registry.db.iterdump())
        self.assertNotIn('private-input-fixture',dump)
        self.assertIn('outcome_uncertain',dump)

    async def test_worker_restart_requires_new_lease(self):
        task,packet=await self.dispatch('vm-fixture-1','reach_run_command',{'command':'fixture'})
        self.fixture.clock.now+=46
        worker=self.fixture.workers['vm-fixture-1']
        self.channel.worker_connect(worker['auth'],{**worker['hello'],'instance_id':'a'*32})
        with self.assertRaises(ChannelDenied):
            await asyncio.wait_for(task,1)
        with self.assertRaises(ChannelDenied):
            self.channel.worker_result(worker['auth'],self.fixture.result(packet))
        self.assertIsNone(self.registry.lease_public('vm-fixture-1'))

    async def test_busy_and_duplicate_poll_isolated(self):
        task,packet=await self.dispatch('vm-fixture-1')
        with self.assertRaises(ChannelDenied):
            await self.channel.request('reach_get_screen_info',{},'vm-fixture-1','42',self.fixture.workers['vm-fixture-1'].get('workflow_token','x'*43))
        second,packet2=await self.dispatch('vm-fixture-2')
        self.channel.worker_result(self.fixture.workers['vm-fixture-2']['auth'],self.fixture.result(packet2))
        await second
        self.channel.worker_result(self.fixture.workers['vm-fixture-1']['auth'],self.fixture.result(packet))
        await task
        worker=self.fixture.workers['vm-fixture-3']
        poll=asyncio.create_task(self.channel.worker_next(worker['auth'],worker['poll'],wait=.05))
        await asyncio.sleep(0)
        with self.assertRaises(ChannelDenied):
            await self.channel.worker_next(worker['auth'],worker['poll'],wait=.01)
        await poll

    async def test_storage_failure_never_leaves_executable_queue(self):
        vm_id='vm-fixture-1'
        with patch.object(self.registry,'create_job',side_effect=OSError('fixture storage failure')):
            with self.assertRaises(OSError):
                await self.channel.request('reach_click',{'x':1,'y':1},vm_id,'42',self.fixture.workers[vm_id]['workflow_token'])
        state=self.channel.state(vm_id)
        self.assertIsNone(state.pending)
        self.assertTrue(state.queue.empty())
        self.fixture.claim(vm_id)
        task=asyncio.create_task(self.channel.request('reach_click',{'x':1,'y':1},vm_id,'42',self.fixture.workers[vm_id]['workflow_token']))
        await asyncio.sleep(0)
        with patch.object(self.registry,'finish_job',side_effect=OSError('fixture storage failure')):
            task.cancel()
            with self.assertRaises(OSError):
                await task
        self.assertIsNone(state.pending)
        self.assertTrue(state.queue.empty())
        worker=self.fixture.workers[vm_id]
        self.assertIsNone(await self.channel.worker_next(worker['auth'],worker['poll'],wait=.01))

    async def test_expired_lease_and_unauthorized_target_no_jobs(self):
        for vm_id,subject in [('vm-fixture-1','43'),('vm-missing','42')]:
            with self.assertRaises(ChannelDenied):
                await self.channel.request('reach_get_screen_info',{},vm_id,subject,self.fixture.workers.get(vm_id,{}).get('workflow_token','x'*43))
        self.fixture.clock.now+=121
        with self.assertRaises(ChannelDenied):
            await self.channel.request('reach_get_screen_info',{},'vm-fixture-1','42',self.fixture.workers['vm-fixture-1'].get('workflow_token','x'*43))
        self.assertEqual(0,self.registry.db.execute('SELECT count(*) FROM jobs').fetchone()[0])


class PrivateBoundary(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture=Fixture()
        self.app=PrivateAPI(self.fixture.channel,['private.example:19444'])
    async def asyncTearDown(self):
        self.fixture.close()
    async def call(self,path,body,patch=None):
        worker=self.fixture.workers['vm-fixture-1']
        scope={'type':'http','method':'POST','path':path,'raw_path':path.encode(),'query_string':b'',
            'headers':[(b'host',b'private.example:19444'),(b'authorization',worker['auth'].encode()),(b'content-type',b'application/json')]}
        if patch:
            scope.update(patch)
        messages=[]
        async def receive():
            return {'type':'http.request','body':body,'more_body':False}
        async def send(value):
            messages.append(value)
        await self.app(scope,receive,send)
        return messages[0]['status']
    async def test_authority_body_and_route_guards(self):
        body=json.dumps(self.fixture.workers['vm-fixture-1']['hello']).encode()
        self.assertEqual(200,await self.call('/worker/connect',body))
        for patch in ({'query_string':b'token=x'},{'raw_path':b'/worker/%63onnect'},{'method':'GET'},
                      {'headers':[(b'host',b'public.example'),(b'content-type',b'application/json')]},
                      {'headers':[(b'host',b'private.example:19444'),(b'authorization',b'Bearer '+'a'.encode()*43),(b'authorization',b'Bearer '+'b'.encode()*43),(b'content-type',b'application/json')]}):
            self.assertEqual(403,await self.call('/worker/connect',body,patch))
        self.assertEqual(403,await self.call('/mcp',body))
        self.assertEqual(403,await self.call('/worker/connect',b'x'*4097))
        self.assertEqual(403,await self.call('/worker/connect',b'{"version":2,"version":2}'))
    async def test_self_revocation_only_own_identity(self):
        self.assertEqual(403,await self.call('/worker/revoke',b'{"version":2,"vm_id":"vm-fixture-2"}'))
        self.assertEqual(200,await self.call('/worker/revoke',b'{"version":2,"vm_id":"vm-fixture-1"}'))
        self.assertEqual(200,await self.call('/worker/revoke',b'{"version":2,"vm_id":"vm-fixture-1"}'))
        self.assertEqual('revoked',self.fixture.channel.discovery('42')[0]['desktop_state'])
        self.assertEqual('ready',self.fixture.channel.discovery('42')[1]['desktop_state'])


if __name__=='__main__':
    unittest.main()
