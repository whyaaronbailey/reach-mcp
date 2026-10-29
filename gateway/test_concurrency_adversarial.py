"""Adversarial workflow fencing with simulated workers; no desktop acceptance."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import threading
import unittest

from channel import Channel, ChannelDenied
from registry import Registry, HEARTBEAT_TTL
from test_registry import Fixture


VM1, VM2, VM3 = ('vm-fixture-1', 'vm-fixture-2', 'vm-fixture-3')


class ReservationAdversarial(unittest.TestCase):
    def setUp(self):
        self.f = Fixture(subjects=['42', '43'])
        self.r = self.f.registry
        self.c = self.f.channel

    def tearDown(self):
        self.f.close()

    def ready(self, vm=VM1, seconds=120):
        self.f.lease(vm)
        return self.f.claim(vm, seconds)

    def heartbeat(self, vm, control):
        worker = self.f.workers[vm]
        worker['poll']['control_id'] = control
        return self.c.worker_heartbeat(worker['auth'], worker['poll'])

    def test_claim_never_creates_owner_authority(self):
        before = self.r.db.execute('SELECT count(*) FROM leases').fetchone()[0]
        for subject in ('42', '43', '999'):
            with self.assertRaises(ChannelDenied):
                self.r.claim(VM1, subject)
        self.assertEqual(before, self.r.db.execute('SELECT count(*) FROM leases').fetchone()[0])
        self.assertEqual(0, self.r.db.execute('SELECT count(*) FROM reservations').fetchone()[0])

    def test_subject_vm_and_capability_are_all_required(self):
        first, second = self.ready(VM1), self.ready(VM2)
        token = first['workflow_token']
        control = self.r.control_public(VM1)['control_id']
        for vm, subject, candidate in (
            (VM2, '42', token), (VM1, '43', token), (VM1, '999', token),
            (VM1, '42', second['workflow_token']), (VM1, '42', control),
            (VM1, '42', 'agent-1'), (VM1, '42', None),
        ):
            with self.subTest(vm=vm, subject=subject, token_type=type(candidate).__name__):
                with self.assertRaises(ChannelDenied):
                    self.r.authorize_reservation(vm, subject, self.c.epoch, candidate)
                with self.assertRaises(ChannelDenied):
                    self.r.renew_claim(vm, subject, candidate)
                with self.assertRaises(ChannelDenied):
                    self.r.release_claim(vm, subject, candidate)
        self.assertTrue(self.r.reservation_status(VM1, '42')['reserved'])
        self.assertTrue(self.r.reservation_status(VM2, '42')['reserved'])

    def test_two_database_connections_atomically_compete_for_same_vm(self):
        self.f.lease(VM1)
        barrier = threading.Barrier(2)
        def attempt():
            registry = Registry(self.f.path, self.f.clock)
            try:
                barrier.wait(timeout=5)
                return registry.claim(VM1, '42', 30)
            finally:
                registry.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual([False, True], sorted(row['claimed'] for row in results))
        self.assertEqual(1, self.r.db.execute('SELECT count(*) FROM reservations').fetchone()[0])
        loser = next(row for row in results if not row['claimed'])
        self.assertNotIn('workflow_token', loser)
        self.assertEqual('preparing', loser['phase'])

    def test_separate_database_connections_claim_different_vms(self):
        for vm in (VM1, VM2):
            self.f.lease(vm)
        barrier = threading.Barrier(2)
        def attempt(vm):
            registry = Registry(self.f.path, self.f.clock)
            try:
                barrier.wait(timeout=5)
                return registry.claim(vm, '42', 30)
            finally:
                registry.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (VM1, VM2)))
        self.assertTrue(all(row['claimed'] for row in results))
        self.assertEqual(2, len({row['workflow_token'] for row in results}))

    def test_preparing_requires_exact_worker_acknowledgment(self):
        self.f.lease(VM1)
        claim = self.r.claim(VM1, '42', 30)
        target = self.r.control_public(VM1)['control_id']
        self.assertEqual('preparing', claim['phase'])
        with self.assertRaises(ChannelDenied):
            self.r.authorize_reservation(VM1, '42', self.c.epoch, claim['workflow_token'])
        with self.assertRaises(ChannelDenied):
            self.heartbeat(VM1, 'f'*32)
        self.heartbeat(VM1, target)
        self.r.authorize_reservation(VM1, '42', self.c.epoch, claim['workflow_token'])
        self.assertEqual('ready', self.r.reservation_status(VM1, '42')['phase'])

    def test_release_requires_idle_ack_before_new_workflow(self):
        first = self.ready()
        old_id = self.r.control_public(VM1)['control_id']
        self.assertEqual('draining', self.r.release_claim(VM1, '42', first['workflow_token'])['phase'])
        self.assertFalse(self.r.claim(VM1, '42')['claimed'])
        self.assertIsNone(self.heartbeat(VM1, old_id)['control'])
        self.assertFalse(self.r.claim(VM1, '42')['claimed'])
        self.heartbeat(VM1, None)  # Simulated native teardown acknowledgment.
        second = self.r.claim(VM1, '42')
        self.assertTrue(second['claimed'])
        new_id = self.r.control_public(VM1)['control_id']
        self.assertNotEqual(old_id, new_id)
        self.assertNotEqual(first['workflow_token'], second['workflow_token'])
        with self.assertRaises(ChannelDenied):
            self.heartbeat(VM1, old_id)
        self.heartbeat(VM1, new_id)
        with self.assertRaises(ChannelDenied):
            self.r.authorize_reservation(VM1, '42', self.c.epoch, first['workflow_token'])

    def test_expired_reservation_cannot_be_renewed_or_replayed(self):
        first = self.ready(seconds=10)
        self.f.clock.now += 11
        self.assertEqual('draining', self.r.reservation_status(VM1, '42')['phase'])
        for action in (self.r.renew_claim, self.r.release_claim):
            with self.assertRaises(ChannelDenied):
                action(VM1, '42', first['workflow_token'])
        self.assertFalse(self.r.claim(VM1, '42')['claimed'])
        self.heartbeat(VM1, None)
        self.assertTrue(self.r.claim(VM1, '42')['claimed'])
        with self.assertRaises(ChannelDenied):
            self.r.authorize_reservation(VM1, '42', self.c.epoch, first['workflow_token'])

    def test_renewal_is_bounded_by_owner_lease_and_valid_duration(self):
        self.f.lease(VM1, 20)
        claim = self.f.claim(VM1, 10)
        self.f.clock.now += 5
        renewed = self.r.renew_claim(VM1, '42', claim['workflow_token'], 600)
        self.assertEqual(self.r.lease_public(VM1)['expires_at'], renewed['expires_at'])
        for seconds in (0, 601, True, 1.5):
            with self.assertRaises(ChannelDenied):
                self.r.renew_claim(VM1, '42', claim['workflow_token'], seconds)
        self.f.clock.now += 16
        with self.assertRaises(ChannelDenied):
            self.r.renew_claim(VM1, '42', claim['workflow_token'], 600)
        with self.assertRaises(ChannelDenied):
            self.r.claim(VM1, '42')

    def test_lease_replacement_fences_old_workflow_until_idle(self):
        first = self.ready()
        old_lease = self.r.lease_public(VM1)['lease_id']
        self.r.authorize_lease(VM1, '43', 120)
        self.assertNotEqual(old_lease, self.r.lease_public(VM1)['lease_id'])
        with self.assertRaises(ChannelDenied):
            self.r.authorize_reservation(VM1, '42', self.c.epoch, first['workflow_token'])
        self.assertFalse(self.r.claim(VM1, '43')['claimed'])
        self.heartbeat(VM1, None)
        second = self.r.claim(VM1, '43')
        self.assertTrue(second['claimed'])
        self.assertNotEqual(first['workflow_token'], second['workflow_token'])

    def test_offline_same_instance_reconnect_cannot_revive_old_capability(self):
        first = self.ready()
        self.f.clock.now += HEARTBEAT_TTL + 1
        worker = self.f.workers[VM1]
        connection = self.c.worker_connect(worker['auth'], worker['hello'])
        self.assertIsNone(connection['control'])
        with self.assertRaises(ChannelDenied):
            self.r.authorize_reservation(VM1, '42', self.c.epoch, first['workflow_token'])
        self.assertEqual(0, self.r.db.execute('SELECT count(*) FROM reservations WHERE vm_id=?', (VM1,)).fetchone()[0])

    def test_stale_session_and_epoch_ack_cannot_release_current_holder(self):
        self.ready()
        worker = self.f.workers[VM1]
        for key, value in (('instance_id', 'f'*32), ('connection_id', 'e'*32),
                           ('gateway_epoch', 'd'*32), ('session_id', 'other-logon')):
            stale = {**worker['poll'], key:value, 'control_id':None}
            with self.assertRaises(ChannelDenied):
                self.c.worker_heartbeat(worker['auth'], stale)
        self.assertEqual('ready', self.r.reservation_status(VM1, '42')['phase'])

    def test_pause_and_revocation_are_independent_of_other_workflows(self):
        first, second = self.ready(VM1), self.ready(VM2)
        self.r.pause(VM1)
        with self.assertRaises(ChannelDenied):
            self.r.authorize_reservation(VM1, '42', self.c.epoch, first['workflow_token'])
        self.r.authorize_reservation(VM2, '42', self.c.epoch, second['workflow_token'])
        self.r.revoke(VM1)
        self.r.authorize_reservation(VM2, '42', self.c.epoch, second['workflow_token'])
        worker = self.f.workers[VM1]
        with self.assertRaises(ChannelDenied):
            self.c.worker_heartbeat(worker['auth'], worker['poll'])

    def test_capability_is_hash_only_in_storage_and_absent_from_discovery(self):
        claim = self.ready()
        token = claim['workflow_token']
        rows = list(self.r.db.iterdump())
        self.assertNotIn(token, '\n'.join(rows))
        stored = self.r.db.execute('SELECT token_hash FROM reservations WHERE vm_id=?', (VM1,)).fetchone()[0]
        self.assertEqual(hashlib.sha256(token.encode()).hexdigest(), stored)
        discovery = json.dumps(self.c.discovery('42'))
        self.assertNotIn(token, discovery)
        self.assertNotIn('token_hash', discovery)
        self.assertNotIn('control_id', discovery)
        self.assertNotIn('workflow_token', json.dumps(self.r.control_public(VM1)))


    def test_stale_expiry_observer_cannot_delete_successor_generation(self):
        first = self.ready(seconds=10)
        self.f.clock.now += 11
        owner = Registry(self.f.path, self.f.clock)
        original = self.r.authorize
        successor = {}
        def authorize_then_owner_replaces(*args, **kwargs):
            lease = original(*args, **kwargs)
            self.r.authorize = original
            owner.pause(VM1)
            w = self.f.workers[VM1]
            owner.connection(w['auth'], {**w['poll'], 'control_id':None}, heartbeat=True)
            owner.authorize_lease(VM1, '42', 120)
            successor.update(owner.claim(VM1, '42', 60))
            return lease
        self.r.authorize = authorize_then_owner_replaces
        try:
            self.r.reservation_status(VM1, '42')
            self.assertTrue(successor['claimed'])
            self.assertTrue(self.r.reservation_status(VM1, '42')['reserved'],
                'An observer of an expired generation must not delete a newer owner-approved workflow.')
            self.assertNotEqual(first['workflow_token'], successor['workflow_token'])
        finally:
            self.r.authorize = original
            owner.close()


    def test_stale_expiry_observer_cannot_delete_explicitly_renewed_holder(self):
        first = self.ready(seconds=10)
        self.f.clock.now += 9
        owner = Registry(self.f.path, self.f.clock)
        original = self.r.authorize
        renewed = {}
        def authorize_then_renew(*args, **kwargs):
            lease = original(*args, **kwargs)
            self.r.authorize = original
            renewed.update(owner.renew_claim(VM1, '42', first['workflow_token'], 60))
            self.f.clock.now += 2  # Old deadline passes only after the valid renewal commits.
            return lease
        self.r.authorize = authorize_then_renew
        try:
            self.r.reservation_status(VM1, '42')
            self.assertTrue(renewed['renewed'])
            self.assertTrue(self.r.reservation_status(VM1, '42')['reserved'])
            self.r.authorize_reservation(VM1, '42', self.c.epoch, first['workflow_token'])
        finally:
            self.r.authorize = original
            owner.close()


class RoutingAdversarial(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.f = Fixture()
        self.r, self.c = self.f.registry, self.f.channel
        self.pending = []
        for vm in (VM1, VM2, VM3):
            self.f.lease(vm)
            self.f.claim(vm)

    async def asyncTearDown(self):
        for task in self.pending:
            if not task.done():
                task.cancel()
        if self.pending:
            await asyncio.gather(*self.pending, return_exceptions=True)
        self.f.close()

    async def request(self, vm):
        task = asyncio.create_task(self.c.request('reach_get_capabilities', {}, vm, '42', self.f.workers[vm]['workflow_token']))
        self.pending.append(task)
        await asyncio.sleep(0)
        return task

    async def next(self, vm):
        w = self.f.workers[vm]
        return await self.c.worker_next(w['auth'], w['poll'], wait=1)

    async def test_three_independent_workflows_interleave_without_cross_target_results(self):
        tasks = {vm:await self.request(vm) for vm in (VM1, VM2, VM3)}
        packets = {vm:await self.next(vm) for vm in (VM3, VM1, VM2)}
        for vm in (VM2, VM3, VM1):
            packet, w = packets[vm], self.f.workers[vm]
            self.assertEqual(vm, packet['vm_id'])
            self.assertEqual(w['poll']['control_id'], packet['control_id'])
            for other in self.f.workers.values():
                self.assertNotIn(other['workflow_token'], json.dumps(packet))
            self.c.worker_result(w['auth'], self.f.result(packet, vm))
        for vm, task in tasks.items():
            result = await task
            self.assertEqual(vm, result['content'][0]['text'])

    async def test_same_vm_second_rpc_does_not_cancel_first_workflow(self):
        first = await self.request(VM1)
        with self.assertRaises(ChannelDenied):
            await self.c.request('reach_get_capabilities', {}, VM1, '42', self.f.workers[VM1]['workflow_token'])
        packet = await self.next(VM1)
        self.c.worker_result(self.f.workers[VM1]['auth'], self.f.result(packet))
        await first
        self.assertEqual('ready', self.r.reservation_status(VM1, '42')['phase'])

    async def test_release_during_delivered_work_marks_uncertain_and_refuses_late_result(self):
        task = await self.request(VM1)
        packet = await self.next(VM1)
        w = self.f.workers[VM1]
        self.r.release_claim(VM1, '42', w['workflow_token'])
        with self.assertRaises(ChannelDenied):
            self.c.worker_result(w['auth'], self.f.result(packet))
        with self.assertRaises(ChannelDenied):
            await task
        state = self.r.db.execute('SELECT state FROM jobs WHERE job_id=?', (packet['job_id'],)).fetchone()[0]
        self.assertEqual('outcome_uncertain', state)
        self.assertFalse(self.r.claim(VM1, '42')['claimed'])
        self.assertTrue(self.r.reservation_status(VM2, '42')['reserved'])

    async def test_cancel_delivered_action_drains_native_context_and_never_requeues(self):
        task = await self.request(VM1)
        packet = await self.next(VM1)
        task.cancel()
        with self.assertRaises(ChannelDenied):
            await task
        self.assertEqual('draining', self.r.reservation_status(VM1, '42')['phase'])
        self.assertIsNone(await self.next(VM1))
        self.assertEqual('outcome_uncertain', self.r.db.execute('SELECT state FROM jobs WHERE job_id=?', (packet['job_id'],)).fetchone()[0])

    async def test_gateway_restart_discards_queued_and_fences_delivered_results(self):
        delivered_task = await self.request(VM1)
        delivered = await self.next(VM1)
        queued_task = await self.request(VM2)
        queued = self.c.state(VM2).pending.packet
        restarted = Channel(self.r)
        self.assertNotEqual(self.c.epoch, restarted.epoch)
        with self.assertRaises(ChannelDenied):
            restarted.worker_result(self.f.workers[VM1]['auth'], self.f.result(delivered))
        for task in (delivered_task, queued_task):
            with self.assertRaises(ChannelDenied):
                await task
        states = dict(self.r.db.execute('SELECT job_id,state FROM jobs'))
        self.assertEqual('outcome_uncertain', states[delivered['job_id']])
        self.assertEqual('discarded', states[queued['job_id']])
        self.assertEqual(0, self.r.db.execute('SELECT count(*) FROM reservations').fetchone()[0])
        self.assertEqual(0, self.r.db.execute('SELECT count(*) FROM leases').fetchone()[0])
        self.assertFalse(restarted.channels)

    async def test_wrong_control_and_other_vm_result_do_not_complete_request(self):
        task = await self.request(VM1)
        packet = await self.next(VM1)
        first, second = self.f.workers[VM1], self.f.workers[VM2]
        for authorization, result in (
            (second['auth'], self.f.result(packet)),
            (first['auth'], {**self.f.result(packet), 'control_id':second['poll']['control_id']}),
        ):
            with self.assertRaises(ChannelDenied):
                self.c.worker_result(authorization, result)
        self.assertFalse(task.done())
        self.c.worker_result(first['auth'], self.f.result(packet))
        await task

    async def test_old_request_cleanup_cannot_abandon_successor_reservation(self):
        task = await self.request(VM1)
        packet = await self.next(VM1)
        w = self.f.workers[VM1]
        self.r.release_claim(VM1, '42', w['workflow_token'])
        w['poll']['control_id'] = None
        self.c.worker_heartbeat(w['auth'], w['poll'])
        successor = self.r.claim(VM1, '42')
        successor_id = self.r.control_public(VM1)['control_id']
        w['poll']['control_id'] = successor_id
        self.c.worker_heartbeat(w['auth'], w['poll'])
        with self.assertRaises(ChannelDenied):
            await task
        self.r.authorize_reservation(VM1, '42', self.c.epoch, successor['workflow_token'])
        self.assertEqual(successor_id, self.r.control_public(VM1)['control_id'])
        with self.assertRaises(ChannelDenied):
            self.c.worker_result(w['auth'], self.f.result(packet))

    async def test_owner_revocation_between_check_and_delivery_blocks_packet(self):
        task = await self.request(VM1)
        original = self.r.deliver_job
        owner = Registry(self.f.path, self.f.clock)
        def revoke_then_deliver(packet):
            owner.pause(VM1)
            return original(packet)
        self.r.deliver_job = revoke_then_deliver
        try:
            with self.assertRaises(ChannelDenied):
                await self.next(VM1)
            with self.assertRaises(ChannelDenied):
                await task
            self.assertFalse(self.c.state(VM1).queue.qsize())
            self.assertEqual('discarded', self.r.db.execute('SELECT state FROM jobs WHERE vm_id=?', (VM1,)).fetchone()[0])
            self.assertTrue(self.r.reservation_status(VM2, '42')['reserved'])
        finally:
            self.r.deliver_job = original
            owner.close()

    async def test_public_claim_uses_verified_subject_and_never_accepts_agent_identity(self):
        from unittest.mock import patch
        from gateway import ReachProvider
        from test_gateway import catalog
        provider = ReachProvider(self.c, catalog())
        claim_tool = await provider._get_tool('reach_claim_vm')
        with patch('gateway.subject', return_value='43'):
            result = await claim_tool.run({'vm_id':VM1})
        self.assertTrue(result.is_error)
        with patch('gateway.subject', return_value='42'):
            result = await claim_tool.run({'vm_id':VM1, 'agent_id':'chosen-client'})
        self.assertTrue(result.is_error)
        self.assertTrue(self.r.reservation_status(VM1, '42')['reserved'])
