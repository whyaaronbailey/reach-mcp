"""Synthetic local fixtures only. No VM, broker socket, credentials or network."""
from contextlib import contextmanager
import asyncio
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT.parent
sys.path.insert(0, str(EDGE))
from registry import Registry
from channel import ChannelDenied
from admin_frontend import ReachAdminFrontend, AdminUnavailable, validate_admin_call
spec = importlib.util.spec_from_file_location('workflow_claim', ROOT / 'core/workflow_claim.py')
claim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(claim)

VM = 'vm-alpha'
OWNER = '424242'
EPOCH, CONTROL, LEASE = 'a' * 32, 'd' * 32, 'e' * 32
CONTEXT = {k: str(i + 1) * 64 for i, k in enumerate(
    ('policy_sha256', 'profile_sha256', 'security_sha256'))}


class Fixture:
    def __init__(self, path=':memory:'):
        self.now = 1000.0
        self.lock = threading.RLock()
        self.enters = 0
        self.registry = Registry(path, clock=lambda: self.now,
            authorization_context=lambda _: CONTEXT.copy(), fence_factory=self.fence)
        self.db = self.registry.db
        self.db.execute("INSERT INTO settings VALUES('gateway_epoch',?)", (EPOCH,))
        self.db.execute('INSERT INTO vms VALUES(?,?,?,?,?,?,?,?,?)',
            (VM, 'Synthetic VM', '2ab91530-757f-5639-b81a-335686c33b2e',
             'S-1-5-21-1-2-3-1005', json.dumps([OWNER]), 'fixture', '0' * 64, 0, 1))
        self.db.execute('INSERT INTO connections VALUES(?,?,?,?,?,?,?,?)',
            (VM, 'b' * 32, 'fixture-session', 'c' * 32, EPOCH, self.now, 'ready', CONTROL))
        self.db.execute('INSERT INTO leases VALUES(?,?,?,?,?,?,?,?,?)',
            (VM, LEASE, OWNER, 900, 2000, 'b' * 32, 'fixture-session', 'c' * 32, EPOCH))
        self.db.execute('INSERT INTO desktop_authorizations VALUES(?,?,?,?,?,?,?,?)',
            (VM, 'f' * 32, OWNER, '2ab91530-757f-5639-b81a-335686c33b2e',
             'S-1-5-21-1-2-3-1005', json.dumps(CONTEXT, sort_keys=True, separators=(',', ':')), 0, 1))
        self.db.execute('INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)',
            (VM, CONTROL, '0' * 64, OWNER, LEASE, EPOCH, 900, 1500))

    @contextmanager
    def fence(self):
        with self.lock:
            self.enters += 1
            yield

    def binding(self):
        return dict(subject=OWNER, vm_id=VM, control_id=CONTROL, lease_id=LEASE,
                    gateway_epoch=EPOCH, expires_at=1500)

    def verify(self, binding=None, callback=None):
        return claim.verify(self.db, binding or self.binding(),
            callback or (lambda _: CONTEXT.copy()), lambda: self.now)

    def close(self):
        self.registry.close()


class ClaimTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()
    def tearDown(self): self.f.close()

    def test_current_claim_and_context(self):
        before = self.f.db.total_changes
        v = self.f.verify()
        self.assertEqual(v['binding']['expires_at'], 1500)
        self.assertEqual(v['anchor']['standing_grant']['grant_id'], 'f' * 32)
        self.assertEqual(self.f.db.total_changes, before)

    def test_submitted_expiry_is_not_authority(self):
        b = self.f.binding(); b['expires_at'] = 99999999
        self.assertEqual(self.f.verify(b)['binding']['expires_at'], 1500)

    def test_expired_old_snapshot_real_renewal_still_uses_db(self):
        b = self.f.binding(); b['expires_at'] = 999
        self.assertEqual(self.f.verify(b)['binding']['expires_at'], 1500)

    def test_no_inbound_approval_field(self):
        b = self.f.binding(); b['approved'] = True
        with self.assertRaisesRegex(claim.ClaimRefused, 'binding-fields'): self.f.verify(b)

    def test_control_lease_epoch_subject_replacements(self):
        for k in ('control_id', 'lease_id', 'gateway_epoch', 'subject'):
            with self.subTest(k=k):
                b = self.f.binding(); b[k] = '9' * 32 if k != 'subject' else '999'
                with self.assertRaises(claim.ClaimRefused): self.f.verify(b)

    def test_release_and_each_missing_live_row(self):
        for table in ('reservations', 'leases', 'connections'):
            self.f.db.execute('SAVEPOINT fixture')
            self.f.db.execute('DELETE FROM ' + table)
            with self.assertRaisesRegex(claim.ClaimRefused, 'live-claim-required'): self.f.verify()
            self.f.db.execute('ROLLBACK TO fixture'); self.f.db.execute('RELEASE fixture')

    def test_expiry_reservation_or_lease(self):
        for table in ('reservations', 'leases'):
            self.f.db.execute('SAVEPOINT fixture')
            self.f.db.execute('UPDATE ' + table + ' SET expires_at=1000')
            with self.assertRaisesRegex(claim.ClaimRefused, 'claim-expired'): self.f.verify()
            self.f.db.execute('ROLLBACK TO fixture'); self.f.db.execute('RELEASE fixture')

    def test_expiry_during_context_read(self):
        def delayed(_): self.f.now = 1500; return CONTEXT.copy()
        with self.assertRaisesRegex(claim.ClaimRefused, 'expired-during-context'): self.f.verify(callback=delayed)

    def test_pause_vm_revoke_and_owner_removal(self):
        for sql in ('UPDATE desktop_authorizations SET paused=1',
                    'UPDATE vms SET revoked=1', "UPDATE vms SET subjects_json='[]'"):
            self.f.db.execute('SAVEPOINT fixture'); self.f.db.execute(sql)
            with self.assertRaises(claim.ClaimRefused): self.f.verify()
            self.f.db.execute('ROLLBACK TO fixture'); self.f.db.execute('RELEASE fixture')

    def test_actual_context_mismatch_refuses(self):
        c = CONTEXT.copy(); c['profile_sha256'] = '0' * 64
        with self.assertRaisesRegex(claim.ClaimRefused, 'actual-context-changed'):
            self.f.verify(callback=lambda _: c)

    def test_grant_identity_and_connection_replacements(self):
        for sql in ("UPDATE desktop_authorizations SET account_sid='other'",
                    "UPDATE connections SET instance_id='other'",
                    "UPDATE connections SET session_id='other'",
                    "UPDATE connections SET control_id='other'",
                    "UPDATE connections SET desktop_state='locked'"):
            self.f.db.execute('SAVEPOINT fixture'); self.f.db.execute(sql)
            with self.assertRaises(claim.ClaimRefused): self.f.verify()
            self.f.db.execute('ROLLBACK TO fixture'); self.f.db.execute('RELEASE fixture')

    def test_stale_and_future_heartbeats(self):
        for when in (954.999, 1000.001):
            self.f.db.execute('UPDATE connections SET last_seen=?', (when,))
            with self.assertRaisesRegex(claim.ClaimRefused, 'connection-heartbeat'): self.f.verify()

    def test_manual_authorized_lease_without_standing_grant(self):
        self.f.db.execute('DELETE FROM desktop_authorizations')
        def forbidden(_): raise AssertionError('not a persistent lease')
        self.assertIsNone(self.f.verify(callback=forbidden)['anchor']['standing_grant'])

    def test_changed_grant_has_changed_anchor(self):
        before = self.f.verify()['anchor']
        self.f.db.execute("UPDATE desktop_authorizations SET grant_id=?", ('9' * 32,))
        self.assertNotEqual(before, self.f.verify()['anchor'])

    def test_replacement_control_never_shares_scope(self):
        b = self.f.binding(); b['control_id'] = '9' * 32
        self.assertNotEqual(claim.scope(self.f.binding()), claim.scope(b))


class OutboxTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()
    def tearDown(self): self.f.close()

    def test_drop_and_event_commit_together(self):
        self.f.registry._drop_reservation(VM)
        self.assertIsNone(self.f.db.execute('SELECT * FROM reservations').fetchone())
        events = self.f.registry.admin_end_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]['binding_json']), self.f.binding())
        self.assertEqual(events[0]['scope'], claim.scope(self.f.binding()))

    def test_drop_rollback_preserves_claim_and_no_event(self):
        with self.assertRaises(RuntimeError):
            with self.f.registry.transaction():
                self.f.registry._drop_reservation(VM)
                raise RuntimeError('synthetic crash before commit')
        self.assertIsNotNone(self.f.db.execute('SELECT * FROM reservations').fetchone())
        self.assertEqual(self.f.registry.admin_end_events(), [])

    def test_exact_ack_only(self):
        self.f.registry._drop_reservation(VM); e = self.f.registry.admin_end_events()[0]
        self.f.registry.acknowledge_admin_end(e['scope'], '{}')
        self.assertEqual(len(self.f.registry.admin_end_events()), 1)
        self.f.registry.acknowledge_admin_end(e['scope'], e['binding_json'])
        self.assertEqual(self.f.registry.admin_end_events(), [])

    def test_stale_expiry_drop_cannot_end_renewed_claim(self):
        self.f.db.execute('UPDATE reservations SET expires_at=1550')
        self.f.registry._drop_reservation(VM, CONTROL, 1500)
        self.assertEqual(self.f.registry.admin_end_events(), [])
        self.assertEqual(self.f.db.execute('SELECT expires_at FROM reservations').fetchone()[0], 1550)

    def test_old_scope_ack_cannot_remove_replacement_event(self):
        self.f.registry._drop_reservation(VM)
        first = self.f.registry.admin_end_events()[0]
        self.f.db.execute('INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)',
            (VM, '9' * 32, '0' * 64, OWNER, LEASE, EPOCH, 900, 1550))
        self.f.registry._drop_reservation(VM)
        self.f.registry.acknowledge_admin_end(first['scope'], first['binding_json'])
        remaining = self.f.registry.admin_end_events()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(json.loads(remaining[0]['binding_json'])['control_id'], '9' * 32)

    def test_pause_revoke_and_gateway_epoch_all_queue_end(self):
        self.f.close()
        for method in ('pause', 'revoke', 'start_gateway'):
            f = Fixture()
            try:
                getattr(f.registry, method)(VM) if method != 'start_gateway' else f.registry.start_gateway()
                self.assertEqual(len(f.registry.admin_end_events()), 1)
            finally: f.close()
        self.f = Fixture()

    def test_outbox_survives_database_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'registry.sqlite3'; f = Fixture(p)
            f.registry._drop_reservation(VM); e = f.registry.admin_end_events(); f.close()
            r = Registry(p, fence_factory=self.f.fence)
            try: self.assertEqual(r.admin_end_events(), e)
            finally: r.close()

    def test_transaction_holds_shared_fence(self):
        before = self.f.enters
        with self.f.registry.transaction():
            self.assertTrue(self.f.lock._is_owned())
        self.assertEqual(self.f.enters, before + 1)


class BrokerFixture:
    def __init__(self, verified=True):
        self.verified = verified; self.mode = 'ask_each'; self.calls = []; self.fail_end = False
        self.count = 0
    async def request(self, value):
        self.calls.append(value)
        command = value['command']
        if command == 'end':
            if self.fail_end: raise AdminUnavailable('synthetic socket loss')
            return {'ok': True, 'durable_reduction_accepted': True, 'state': 'ended'}
        if command == 'revoke':
            self.mode = 'ask_each'
            return {'ok': True, 'durable_reduction_accepted': True, 'state': 'revoked'}
        if command == 'prepare':
            self.count += 1
            return {'ok': True, 'operation_id': format(self.count, '032x'),
                'request_sha256': 'f' * 64, 'approval_nonce': format(self.count + 100, '032x'),
                'permission_mode': self.mode, 'workflow_release_verified': self.verified}
        if command == 'execute':
            if value['choice'] == 'workflow': self.mode = 'workflow'
            if value['choice'] is None and self.mode != 'workflow': raise AssertionError('missing human grant')
            return {'ok': True, 'job_id': format(self.count, '032x')}
        raise AssertionError(command)


class Object:
    def __init__(self, **kw): self.__dict__.update(kw)


class FrontendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.f = Fixture(); self.b = BrokerFixture(); self.front = ReachAdminFrontend(
            Object(registry=self.f.registry, epoch=EPOCH), self.b, clock=lambda: self.f.now)
        self.args = {'vm_id': VM, 'workflow_token': 'x' * 43, 'script': 'synthetic:no-execution'}
        # Only test the existing internal registry authorization call with a
        # synthetic token fixture; no RPC transport/context seals are fabricated.
        self.f.registry.authorize_reservation = lambda *a, **k: (
            {'lease_id': LEASE}, {'control_id': CONTROL, 'gateway_epoch': EPOCH, 'expires_at': 1500})
        module = types.ModuleType('mcp.types')
        module.InputRequiredResult = module.ElicitRequest = module.ElicitRequestFormParams = Object
        self.modules = {k: sys.modules.get(k) for k in ('mcp', 'mcp.types')}
        sys.modules['mcp'] = types.ModuleType('mcp'); sys.modules['mcp.types'] = module
    def tearDown(self):
        self.f.close()
        for k,v in self.modules.items():
            if v is None: sys.modules.pop(k, None)
            else: sys.modules[k] = v
    def ctx(self, state=None, answer=None):
        return Object(request_context=Object(protocol_version='2026-07-28',
            session=Object(client_capabilities={'elicitation': {'form': {}}})),
            request_state=state, input_responses=answer)

    async def test_native_workflow_choice_then_unlimited_distinct_operations(self):
        form = await self.front.run('reach_run_admin', self.args, OWNER, self.ctx())
        schema = form.input_requests['owner_admin'].params.requested_schema
        self.assertEqual(schema['properties']['choice']['enum'], ['once', 'workflow', 'deny'])
        answer = {'owner_admin': Object(action='accept', content={'choice': 'workflow'})}
        await self.front.run('reach_run_admin', self.args, OWNER, self.ctx(form.request_state, answer))
        for i in range(3):
            args = {**self.args, 'script': 'synthetic-operation-' + str(i)}
            await self.front.run('reach_run_admin', args, OWNER, self.ctx())
        executions = [v for v in self.b.calls if v['command'] == 'execute']
        self.assertEqual([v['choice'] for v in executions], ['workflow', None, None, None])

    async def test_unverified_workflow_not_offered(self):
        self.b.verified = False
        form = await self.front.run('reach_run_admin', self.args, OWNER, self.ctx())
        self.assertEqual(form.input_requests['owner_admin'].params.requested_schema[
            'properties']['choice']['enum'], ['once', 'deny'])

    async def test_unsupported_form_refuses_before_prepare(self):
        c = self.ctx(); c.request_context.protocol_version = 'older'
        with self.assertRaises(AdminUnavailable): await self.front.run('reach_run_admin', self.args, OWNER, c)
        self.assertEqual(self.b.calls, [])

    async def test_modified_script_and_replayed_continuation_refuse(self):
        form = await self.front.run('reach_run_admin', self.args, OWNER, self.ctx())
        ans = {'owner_admin': Object(action='accept', content={'choice': 'once'})}
        with self.assertRaises(ChannelDenied):
            await self.front.run('reach_run_admin', {**self.args, 'script': 'changed'}, OWNER,
                self.ctx(form.request_state, ans))
        with self.assertRaises(ChannelDenied):
            await self.front.run('reach_run_admin', self.args, OWNER, self.ctx(form.request_state, ans))
        self.assertFalse(any(v['command'] == 'execute' for v in self.b.calls))

    async def test_revoke_consumes_pending_and_next_operation_asks_again(self):
        form = await self.front.run('reach_run_admin', self.args, OWNER, self.ctx())
        await self.front.run('reach_revoke_admin', {k:self.args[k] for k in ('vm_id','workflow_token')}, OWNER, self.ctx())
        ans = {'owner_admin': Object(action='accept', content={'choice': 'workflow'})}
        with self.assertRaises(ChannelDenied):
            await self.front.run('reach_run_admin', self.args, OWNER, self.ctx(form.request_state, ans))
        next_form = await self.front.run('reach_run_admin', self.args, OWNER, self.ctx())
        self.assertIsInstance(next_form, Object)

    async def test_lost_end_ack_retains_tracking_and_durable_retry(self):
        binding = self.f.binding(); self.front.tracked.add(tuple(binding[k] for k in claim.IDENTITY))
        self.f.registry._drop_reservation(VM); self.b.fail_end = True
        await self.front.flush_reductions()
        self.assertEqual(len(self.f.registry.admin_end_events()), 1)
        self.assertEqual(len(self.front.tracked), 1)
        self.b.fail_end = False; await self.front.flush_reductions()
        self.assertEqual(self.f.registry.admin_end_events(), [])
        self.assertEqual(self.front.tracked, set())
        self.assertEqual([v['command'] for v in self.b.calls], ['end','end'])

    async def test_extra_approval_and_lifecycle_arguments_refused(self):
        for k in ('approved', 'lifecycle_verified', 'native_session_id'):
            with self.assertRaises(ChannelDenied): validate_admin_call('reach_run_admin', {**self.args, k: True})


if __name__ == '__main__': unittest.main()
