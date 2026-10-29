"""Standing owner consent survives reconnects, never workflow generations."""
import asyncio
import copy
import io
import sys
import unittest
from unittest.mock import Mock, patch

import admin
from channel import Channel, ChannelDenied, MAX_LEASE
from registry import CONNECTION_KEYS, Registry
from test_deployment_policy import fixture_policy, fixture_profile, fixture_runtime, OBS
from test_registry import Fixture


def binding():
    return {'policy_sha256':'a'*64,'profile_sha256':'b'*64,'security_sha256':'c'*64}


class PersistentAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture(count=2,subjects=['42','43'])
        self.registry = self.fixture.registry
        self.worker = self.fixture.workers['vm-fixture-1']
        self.current = {vm_id:binding() for vm_id in self.fixture.workers}
        self.registry.authorization_context = lambda vm_id:copy.deepcopy(self.current[vm_id])

    def tearDown(self):
        self.fixture.close()

    def grant(self,vm_id='vm-fixture-1'):
        connection = self.registry.owner_connection(vm_id)
        return self.registry.authorize_persistent(vm_id,'42',self.current[vm_id],
            {key:connection[key] for key in ('connection_id','gateway_epoch')})

    def heartbeat(self,state='ready'):
        return self.fixture.channel.worker_heartbeat(self.worker['auth'],
            {**self.worker['poll'],'desktop_state':state})

    def test_standing_authorization_has_no_expiry_but_session_lease_is_bounded(self):
        self.assertIsNone(self.registry.lease_public('vm-fixture-1'))
        value = self.grant()
        self.assertTrue(value['persistent'])
        self.assertIsNone(value['expires_at'])
        lease = self.registry.lease_public('vm-fixture-1')
        self.assertEqual(MAX_LEASE,lease['expires_at']-self.fixture.clock.now)
        status = self.registry.list_vms('42')[0]
        self.assertEqual({'mode':'persistent','persistent':True,'expires_at':None,'paused':False},
                         status['desktop_authorization'])
        self.assertTrue(status['desktop_authorized'])
        self.assertFalse(self.registry.list_vms('43')[0]['desktop_authorized'])
        with self.assertRaises(ChannelDenied):
            self.registry.claim('vm-fixture-1','43')
        self.assertFalse(self.registry.list_vms('42')[1]['desktop_authorized'])

    def test_grant_requires_current_protected_context_subject_and_exact_connection(self):
        connection = self.registry.owner_connection('vm-fixture-1')
        expected = {key:connection[key] for key in ('connection_id','gateway_epoch')}
        for subject,selected,target in (
                ('999',binding(),expected),
                ('42',{**binding(),'security_sha256':'d'*64},expected),
                ('42',binding(),{**expected,'connection_id':'e'*32})):
            with self.subTest(subject=subject,selected=selected,target=target),self.assertRaises(ChannelDenied):
                self.registry.authorize_persistent('vm-fixture-1',subject,selected,target)
        self.registry.authorization_context = None
        with self.assertRaises(ChannelDenied):
            self.grant()
        self.assertIsNone(self.registry.lease_public('vm-fixture-1'))

    def test_automatic_lease_maintenance_passes_original_expiry_without_owner_renewal(self):
        self.grant()
        original = self.registry.lease_public('vm-fixture-1')
        for _ in range(220):
            self.fixture.clock.now += 30
            self.heartbeat()
        self.fixture.claim('vm-fixture-1',600)
        control = self.registry.control_public('vm-fixture-1')['control_id']
        for index in range(30):
            self.fixture.clock.now += 30
            if index in (10,20):
                self.registry.renew_claim('vm-fixture-1','42',self.worker['workflow_token'],600)
            self.heartbeat()
        current = self.registry.lease_public('vm-fixture-1')
        self.assertGreater(self.fixture.clock.now,original['expires_at'])
        self.assertEqual(original['lease_id'],current['lease_id'])
        self.assertEqual(control,self.registry.control_public('vm-fixture-1')['control_id'])
        self.assertGreater(current['expires_at'],original['expires_at'])
        self.assertLessEqual(current['expires_at']-self.fixture.clock.now,MAX_LEASE)

    def test_expired_session_reconnect_gets_fresh_lease_and_cannot_resurrect_claim(self):
        self.grant()
        original = self.registry.lease_public('vm-fixture-1')
        old_token = self.fixture.claim('vm-fixture-1')['workflow_token']
        self.fixture.clock.now = original['expires_at']+1
        connection = self.fixture.channel.worker_connect(self.worker['auth'],self.worker['hello'])
        self.assertIsNotNone(connection['lease'])
        self.assertNotEqual(original['lease_id'],connection['lease']['lease_id'])
        self.assertIsNone(connection['control'])
        with self.assertRaises(ChannelDenied):
            self.registry.renew_claim('vm-fixture-1','42',old_token)

    def test_gateway_restart_and_new_registry_preserve_grant_but_fence_old_session(self):
        self.grant()
        lease = self.registry.lease_public('vm-fixture-1')
        token = self.fixture.claim('vm-fixture-1')['workflow_token']
        other = Registry(self.fixture.path,self.fixture.clock,
            authorization_context=self.registry.authorization_context)
        try:
            restarted = Channel(other)
            self.assertIsNone(other.lease_public('vm-fixture-1'))
            connection = restarted.worker_connect(self.worker['auth'],self.worker['hello'])
            current = connection['lease']
            self.assertNotEqual(lease['lease_id'],current['lease_id'])
            self.assertNotEqual(lease['gateway_epoch'],current['gateway_epoch'])
            self.assertEqual(connection['connection_id'],current['connection_id'])
            self.assertIsNone(connection['control'])
            with self.assertRaises(ChannelDenied):
                other.renew_claim('vm-fixture-1','42',token)
            with self.assertRaises(ChannelDenied):
                other.connection(self.worker['auth'],
                    {key:self.worker['poll'][key] for key in CONNECTION_KEYS})
        finally:
            other.close()

    def test_lock_and_replacement_worker_restore_only_standing_authority(self):
        self.grant()
        first = self.registry.lease_public('vm-fixture-1')
        token = self.fixture.claim('vm-fixture-1')['workflow_token']
        self.assertIsNone(self.heartbeat('locked')['lease'])
        self.worker['poll']['control_id'] = None
        ready = self.heartbeat()['lease']
        self.assertIsNotNone(ready)
        self.assertNotEqual(first['lease_id'],ready['lease_id'])
        with self.assertRaises(ChannelDenied):
            self.registry.renew_claim('vm-fixture-1','42',token)
        self.fixture.clock.now += 46
        connection = self.fixture.channel.worker_connect(self.worker['auth'],
            {**self.worker['hello'],'instance_id':'e'*32,'session_id':'boot-2:logon-1'})
        self.assertNotEqual(ready['lease_id'],connection['lease']['lease_id'])
        self.assertEqual('e'*32,connection['lease']['instance_id'])

    def test_pause_is_sticky_across_heartbeat_reconnect_and_gateway_restart(self):
        self.grant()
        self.registry.pause('vm-fixture-1')
        self.assertIsNone(self.heartbeat()['lease'])
        self.assertIsNone(self.fixture.channel.worker_connect(self.worker['auth'],self.worker['hello'])['lease'])
        restarted = Channel(self.registry)
        self.assertIsNone(restarted.worker_connect(self.worker['auth'],self.worker['hello'])['lease'])
        status = self.registry.list_vms('42')[0]
        self.assertTrue(status['desktop_authorization']['paused'])
        self.assertFalse(status['desktop_authorized'])
        # Only a new explicit owner grant can resume standing authorization.
        self.grant()
        self.assertTrue(self.registry.list_vms('42')[0]['desktop_authorized'])

    def test_legacy_temporary_lease_cannot_replace_persistent_mode_or_undo_pause(self):
        self.grant()
        original = self.registry.lease_public('vm-fixture-1')
        with self.assertRaises(ChannelDenied):
            self.registry.authorize_lease('vm-fixture-1','42',60)
        self.assertEqual(original['lease_id'],self.registry.lease_public('vm-fixture-1')['lease_id'])
        self.registry.pause('vm-fixture-1')
        with self.assertRaises(ChannelDenied):
            self.registry.authorize_lease('vm-fixture-1','42',60)
        self.assertIsNone(self.heartbeat()['lease'])
        self.registry.revoke_persistent('vm-fixture-1')
        temporary = self.registry.authorize_lease('vm-fixture-1','42',60)
        self.assertEqual(60,temporary['expires_at']-self.fixture.clock.now)

    def test_revoke_and_enrollment_rotation_remove_standing_authority(self):
        self.grant()
        self.registry.revoke_persistent('vm-fixture-1')
        self.assertIsNone(self.heartbeat()['lease'])
        self.grant()
        self.registry.revoke('vm-fixture-1')
        self.assertEqual(0,self.registry.db.execute('SELECT count(*) FROM desktop_authorizations').fetchone()[0])
        identity = self.worker['identity']
        grant = self.registry.grant('vm-fixture-1','Re-enrolled',identity['machine_uuid'],identity['account_sid'],['42'])
        credentials = self.registry.enroll('Bearer '+grant['enrollment_token'],identity)
        self.assertIsNone(self.fixture.channel.worker_connect('Bearer '+credentials['worker_token'],self.worker['hello'])['lease'])
        # A live credential rotation must also erase an existing standing grant.
        self.grant()
        grant = self.registry.grant('vm-fixture-1','Rotated',identity['machine_uuid'],identity['account_sid'],['42'])
        self.registry.enroll('Bearer '+grant['enrollment_token'],identity)
        self.assertEqual(0,self.registry.db.execute('SELECT count(*) FROM desktop_authorizations').fetchone()[0])

    def test_context_drift_or_unavailable_reader_fences_active_claim_immediately(self):
        self.grant()
        self.grant('vm-fixture-2')
        self.fixture.claim('vm-fixture-1')
        for field in binding():
            original = self.current['vm-fixture-1'][field]
            self.current['vm-fixture-1'][field] = 'e'*64
            self.assertIsNone(self.registry.lease_public('vm-fixture-1'))
            self.assertIsNone(self.registry.control_public('vm-fixture-1'))
            self.assertTrue(self.registry.list_vms('42')[1]['desktop_authorized'])
            self.current['vm-fixture-1'][field] = original
            self.assertIsNotNone(self.heartbeat()['lease'])
        with patch.object(self.registry,'authorization_context',side_effect=OSError('protected input unavailable')):
            self.assertIsNone(self.registry.lease_public('vm-fixture-1'))
        self.assertIsNotNone(self.heartbeat()['lease'])


class PersistentReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_restart_discards_delivered_work_and_never_replays_it(self):
        fixture = Fixture(count=1)
        try:
            registry = fixture.registry
            registry.authorization_context = lambda vm_id:binding()
            vm_id = 'vm-fixture-1'
            worker = fixture.workers[vm_id]
            connection = registry.owner_connection(vm_id)
            registry.authorize_persistent(vm_id,'42',binding(),
                {key:connection[key] for key in ('connection_id','gateway_epoch')})
            token = fixture.claim(vm_id)['workflow_token']
            task = asyncio.create_task(fixture.channel.request('reach_click',{'x':1,'y':1},vm_id,'42',token))
            packet = await fixture.channel.worker_next(worker['auth'],worker['poll'],wait=1)
            restarted = Channel(registry)
            with self.assertRaises(ChannelDenied):
                await asyncio.wait_for(task,1)
            self.assertEqual('outcome_uncertain',registry.db.execute(
                'SELECT state FROM jobs WHERE job_id=?',(packet['job_id'],)).fetchone()[0])
            fresh = restarted.worker_connect(worker['auth'],worker['hello'])
            self.assertIsNotNone(fresh['lease'])
            self.assertIsNone(fresh['control'])
            with self.assertRaises(ChannelDenied):
                restarted.worker_result(worker['auth'],fixture.result(packet))
            self.assertTrue(restarted.state(vm_id).queue.empty())
        finally:
            fixture.close()


class PersistentOwnerConsoleTests(unittest.TestCase):
    def test_persistent_cli_requires_verified_fresh_proof_before_registry_grant(self):
        registry = Mock()
        context = {'policy':fixture_policy(),'runtime':fixture_runtime(fixture_policy()),'observation':OBS}
        proof = {'connection_id':'a'*32,'gateway_epoch':'b'*32}
        for rejected in (True,False):
            registry.reset_mock()
            with patch.object(sys,'argv',['admin.py','authorize-persistent','--vm-id','vm-1','--subject','123']), \
                    patch.object(admin,'Registry',return_value=registry), \
                    patch.object(admin,'protected_file',side_effect=lambda path:proof if '/proofs/' in path else fixture_profile()), \
                    patch.object(admin,'deployment_context',return_value=context), \
                    patch.object(admin,'persistent_context',return_value=binding()), \
                    patch.object(admin,'verify_network_proof',side_effect=ChannelDenied() if rejected else None) as verify, \
                    patch.object(sys,'stdout',io.StringIO()):
                if rejected:
                    with self.assertRaises(ChannelDenied):
                        admin.main()
                    registry.authorize_persistent.assert_not_called()
                else:
                    registry.authorize_persistent.return_value = {'persistent':True,'expires_at':None}
                    admin.main()
                    registry.authorize_persistent.assert_called_once_with('vm-1','123',binding(),expected_connection=proof)
                verify.assert_called_once()
                registry.close.assert_called_once()

    def test_stable_context_excludes_runtime_generation_but_binds_security_and_profile(self):
        shared = fixture_policy()
        selected = fixture_profile()
        security = {key:shared[key] for key in ('manifest_sha256','transport_sha256')}
        context = {'policy':shared,'runtime':fixture_runtime(shared),'observation':OBS}
        with patch.object(admin,'deployment_context',return_value=context), \
                patch.object(admin,'protected_file',side_effect=lambda path:security if path.endswith('security.json') else selected):
            first = admin.persistent_context('vm-1')
            context['runtime']['container_id'] = '9'*64
            context['runtime']['checked_at'] += 300
            self.assertEqual(first,admin.persistent_context('vm-1'))
            security['extra_security_control'] = True
            self.assertNotEqual(first,admin.persistent_context('vm-1'))
            security.pop('extra_security_control')
            selected['enabled'] = False
            with self.assertRaises(ChannelDenied):
                admin.persistent_context('vm-1')


if __name__ == '__main__':
    unittest.main()
