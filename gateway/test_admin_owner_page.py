"""Owner-page frontend fences; no live portal, broker or VM is contacted."""
import asyncio
import base64
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx
from fastmcp import FastMCP
from mcp.types import InputRequiredResult

from admin_frontend import (AdminUnavailable, OWNER_APPROVAL_BASE, ReachAdminFrontend,
    form_metadata_scope, install_form_metadata, validate_admin_call)
from channel import ChannelDenied
from gateway import ReachProvider
from test_admin_frontend import Broker, Registry, identity
from test_admin_approval_transport import OPENAI_CAPS, USER_VERIFICATION_ONLY_CAPS, context
from test_gateway import catalog


class OwnerPageFrontendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = 100
        self.registry = Registry(lambda: self.now)
        self.channel = SimpleNamespace(registry=self.registry, epoch='e' * 32)
        self.broker = Broker()
        self.broker.workflow_release_verified = False
        self.records = []
        self.front = ReachAdminFrontend(self.channel, self.broker, clock=lambda: self.now,
            diagnostics=self.records.append, portal_enabled=True)
        self.args = {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43,
            'script': 'whoami /groups', 'arguments': ['private-argument'], 'timeout_seconds': 30}

    async def ask(self, capabilities=USER_VERIFICATION_ONLY_CAPS):
        value = await self.front.run('reach_run_admin', self.args, '42', context(capabilities=capabilities))
        self.assertEqual('awaiting_owner_approval', value['state'])
        self.assertRegex(value['job_id'], '^[a-f0-9]{32}$')
        self.assertEqual(OWNER_APPROVAL_BASE + '/' + value['job_id'], value['approval_url'])
        self.assertFalse(value['administrator_permission_granted'])
        return value['job_id']

    async def status(self, request_id):
        return await self.front.run('reach_admin_status', {'vm_id': self.args['vm_id'],
            'workflow_token': self.args['workflow_token'], 'job_id': request_id}, '42', context())

    async def test_pending_review_and_poll_prepare_exact_operation_only_once(self):
        request_id = await self.ask()
        for _ in range(3):
            self.assertEqual('awaiting_owner_approval', (await self.status(request_id))['state'])
        review = await self.front.portal_get(request_id, '42')
        self.assertEqual('awaiting_owner', review['state'])
        self.assertEqual(self.args['script'], review['script'])
        self.assertEqual(self.args['arguments'], review['arguments'])
        self.assertEqual(30, review['timeout_seconds'])
        self.assertRegex(review['request_sha256'], '^[a-f0-9]{64}$')
        for secret in ('t' * 43, 'approval_nonce', 'control_id', 'lease_id'):
            self.assertNotIn(secret, json.dumps(review))
        self.assertEqual(['prepare'], [call['command'] for call in self.broker.calls])
        self.assertEqual(self.args['script'], base64.b64decode(self.broker.calls[0]['script_base64']).decode())
        self.assertFalse(self.broker.dispatched)

    async def test_owner_accept_dispatches_once_and_status_maps_same_broker_job(self):
        request_id = await self.ask()
        result = await self.front.portal_decide(request_id, '42', 'once')
        self.assertEqual('running', result['state'])
        self.assertEqual(1, len(self.broker.dispatched))
        self.assertEqual('once', self.broker.dispatched[0]['choice'])
        self.assertEqual('Reach owner page:' + request_id, self.broker.dispatched[0]['approval_reference'])
        broker_id = self.broker.dispatched[0]['operation_id']
        self.assertEqual(broker_id, result['job_id'])
        self.assertEqual('running', (await self.front.portal_decide(request_id, '42', 'once'))['state'])
        polled = await self.status(request_id)
        self.assertEqual(('completed', broker_id, request_id),
            (polled['state'], polled['job_id'], polled['approval_request_id']))
        self.assertEqual(1, sum(call['command'] == 'prepare' for call in self.broker.calls))
        self.assertEqual(1, len(self.broker.dispatched))
        self.assertFalse(self.broker.grants)

    async def test_owner_deny_is_terminal_and_cannot_be_replayed_as_accept(self):
        request_id = await self.ask()
        self.assertEqual('declined', (await self.front.portal_decide(request_id, '42', 'deny'))['state'])
        self.assertEqual('declined', (await self.front.portal_decide(request_id, '42', 'once'))['state'])
        self.assertEqual('declined', (await self.status(request_id))['state'])
        self.assertFalse(self.broker.dispatched)

    async def test_browser_owner_and_live_claim_generation_are_independently_required(self):
        request_id = await self.ask()
        with self.assertRaises(ChannelDenied):
            await self.front.portal_get(request_id, '43')
        with self.assertRaises(ChannelDenied):
            await self.front.portal_decide(request_id, '43', 'once')
        self.registry.control_id = 'd' * 32
        with self.assertRaises(ChannelDenied):
            await self.front.portal_get(request_id, '42')
        self.assertEqual('unavailable', (await self.front.portal_decide(request_id, '42', 'once'))['state'])
        self.assertFalse(self.broker.dispatched)

    async def test_claim_is_rechecked_again_at_post_even_after_valid_review(self):
        request_id = await self.ask()
        await self.front.portal_get(request_id, '42')
        self.registry.valid = False
        with self.assertRaises(ChannelDenied):
            await self.front.portal_decide(request_id, '42', 'once')
        self.assertFalse(self.broker.dispatched)

    async def test_expiry_release_and_revoke_invalidate_pending_links(self):
        request_id = await self.ask()
        self.now = 501
        self.assertEqual({'state': 'expired'}, await self.front.portal_get(request_id, '42'))
        self.assertEqual('expired', (await self.front.portal_decide(request_id, '42', 'once'))['state'])
        self.now = 100
        released = await self.ask()
        await self.front.end(self.front.binding('42', self.args))
        self.assertEqual({'state': 'released'}, await self.front.portal_get(released, '42'))
        self.assertEqual('released', (await self.front.portal_decide(released, '42', 'once'))['state'])
        revoked = await self.ask()
        await self.front.run('reach_revoke_admin', {'vm_id': self.args['vm_id'],
            'workflow_token': self.args['workflow_token']}, '42', context())
        self.assertEqual({'state': 'revoked'}, await self.front.portal_get(revoked, '42'))
        self.assertEqual('revoked', (await self.status(revoked))['state'])
        self.assertFalse(self.broker.dispatched)

    async def test_terminal_rows_are_not_an_operation_limit(self):
        for _ in range(3):
            request_id = await self.ask()
            await self.front.portal_decide(request_id, '42', 'once')
            self.assertEqual('completed', (await self.status(request_id))['state'])
        self.assertEqual(3, len(self.broker.dispatched))
        self.assertFalse(self.broker.grants)

    async def test_verified_owner_session_reuses_grant_without_another_page(self):
        self.broker.workflow_release_verified = True
        request_id = await self.ask()
        self.assertTrue((await self.front.portal_get(request_id, '42'))['session_allowed'])
        await self.front.portal_decide(request_id, '42', 'workflow')
        for _ in range(3):
            result = await self.front.run('reach_run_admin', self.args, '42', context(capabilities=USER_VERIFICATION_ONLY_CAPS))
            self.assertEqual('running', result['state'])
        self.assertEqual(['workflow',None,None,None], [v['choice'] for v in self.broker.dispatched])
        self.assertEqual(1, len(self.front.portal_entries))

    async def test_uncertain_dispatch_is_consumed_and_never_replayed(self):
        real = self.broker.request
        async def uncertain(value):
            result = await real(value)
            if value['command'] == 'execute':
                raise AdminUnavailable('Reply lost after dispatch.')
            return result
        self.broker.request = uncertain
        request_id = await self.ask()
        self.assertEqual('outcome_uncertain', (await self.front.portal_decide(request_id, '42', 'once'))['state'])
        self.assertEqual('outcome_uncertain', (await self.front.portal_decide(request_id, '42', 'once'))['state'])
        self.assertEqual('outcome_uncertain', (await self.status(request_id))['state'])
        self.assertEqual(1, len(self.broker.dispatched))

    async def test_cancellation_after_dispatch_cannot_replay_owner_decision(self):
        sent = asyncio.Event()
        real = self.broker.request
        async def delayed(value):
            result = await real(value)
            if value['command'] == 'execute':
                sent.set()
                await asyncio.Future()
            return result
        self.broker.request = delayed
        request_id = await self.ask()
        task = asyncio.create_task(self.front.portal_decide(request_id, '42', 'once'))
        await sent.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual('outcome_uncertain', (await self.front.portal_decide(request_id, '42', 'once'))['state'])
        self.assertEqual(1, len(self.broker.dispatched))

    async def test_agent_arguments_and_native_continuation_cannot_approve_owner_page(self):
        request_id = await self.ask()
        for extra in ({'choice': 'once'}, {'approval_reference': 'Reach owner page:' + request_id}):
            with self.assertRaises(ChannelDenied):
                validate_admin_call('reach_run_admin', {**self.args, **extra})
        with self.assertRaises(AdminUnavailable):
            await self.front.run('reach_run_admin', self.args, '42',
                context('forged-state', 'accept', 'once', capabilities=USER_VERIFICATION_ONLY_CAPS))
        self.assertFalse(self.broker.dispatched)
        self.assertEqual(['prepare'], [call['command'] for call in self.broker.calls])

    async def test_review_is_captured_not_mutable_caller_input(self):
        request_id = await self.ask()
        self.args['script'] = 'different-script'
        self.args['arguments'].append('different-argument')
        review = await self.front.portal_get(request_id, '42')
        self.assertEqual('whoami /groups', review['script'])
        self.assertEqual(['private-argument'], review['arguments'])
        review['arguments'].append('browser-output-mutation')
        self.assertEqual(['private-argument'], (await self.front.portal_get(request_id, '42'))['arguments'])

    async def test_explicit_native_forms_still_use_native_flow(self):
        with form_metadata_scope():
            result = await self.front.run('reach_run_admin', self.args, '42', context(capabilities=OPENAI_CAPS))
        self.assertIsInstance(result, InputRequiredResult)
        self.assertFalse(self.front.portal_entries)
        self.assertFalse(self.broker.dispatched)

    async def test_standard_core_form_uses_owner_page_without_native_form(self):
        request_id = await self.ask(capabilities={'elicitation': {'form': {}}})
        self.assertEqual('awaiting_owner', (await self.front.portal_get(request_id, '42'))['state'])
        self.assertEqual(['prepare'], [call['command'] for call in self.broker.calls])
        self.assertFalse(self.broker.dispatched)

    async def test_native_explicit_deny_with_extra_fields_never_reprompts(self):
        with form_metadata_scope():
            first = await self.front.run('reach_run_admin', self.args, '42', context(capabilities=OPENAI_CAPS))
            answer = context(first.request_state, 'accept', capabilities=OPENAI_CAPS)
            answer.input_responses['owner_admin'] = {'action': 'accept',
                'content': {'choice': 'deny', 'extra': 'untrusted'}}
            result = await self.front.run('reach_run_admin', self.args, '42', answer)
            self.assertEqual('declined', result['state'])
            self.assertFalse(result['administrator_permission_granted'])
            with self.assertRaises(ChannelDenied):
                await self.front.run('reach_run_admin', self.args, '42', answer)
        self.assertFalse(self.front.portal_entries)
        self.assertFalse(self.broker.dispatched)
        self.assertEqual(['prepare'], [call['command'] for call in self.broker.calls])

    async def test_malformed_native_accept_reuses_preparation_but_requires_owner_page_post(self):
        with form_metadata_scope():
            first = await self.front.run('reach_run_admin', self.args, '42', context(capabilities=OPENAI_CAPS))
            bad = context(first.request_state, 'accept', capabilities=OPENAI_CAPS)
            bad.input_responses['owner_admin'] = {'action': 'accept', 'content': {}}
            pending = await self.front.run('reach_run_admin', self.args, '42', bad)
            self.assertEqual('awaiting_owner_approval', pending['state'])
            self.assertNotEqual(json.loads(first.request_state)['nonce'], pending['job_id'])
            self.assertFalse(self.broker.dispatched)
            self.assertEqual(['prepare'], [call['command'] for call in self.broker.calls])
            with self.assertRaises(ChannelDenied):
                await self.front.run('reach_run_admin', self.args, '42',
                    context(first.request_state, 'accept', 'once', capabilities=OPENAI_CAPS))
        await self.front.portal_decide(pending['job_id'], '42', 'once')
        self.assertEqual(1, len(self.broker.dispatched))
        self.assertEqual(1, sum(call['command'] == 'prepare' for call in self.broker.calls))

    async def test_native_decline_and_cancel_never_redirect_to_another_approval(self):
        with form_metadata_scope():
            for action, expected in (('decline', 'declined'), ('cancel', 'cancelled')):
                first = await self.front.run('reach_run_admin', self.args, '42', context(capabilities=OPENAI_CAPS))
                result = await self.front.run('reach_run_admin', self.args, '42',
                    context(first.request_state, action, capabilities=OPENAI_CAPS))
                self.assertEqual(expected, result['state'])
        self.assertFalse(self.front.portal_entries)
        self.assertFalse(self.broker.dispatched)


class OwnerPageWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_http_unsupported_form_returns_link_and_status_never_submits(self):
        registry = Registry(lambda: 100)
        channel = SimpleNamespace(registry=registry, epoch='e' * 32)
        broker = Broker()
        broker.workflow_release_verified = False
        front = ReachAdminFrontend(channel, broker, clock=lambda: 100, portal_enabled=True)
        server = FastMCP('owner-page-fixture', providers=[ReachProvider(channel, catalog(), admin=front)])
        install_form_metadata(server)
        app = server.http_app(path='/mcp', stateless_http=True, json_response=True)
        async def post(name, arguments):
            payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name,
                'arguments': arguments, '_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                'io.modelcontextprotocol/clientInfo': {'name': 'owner-page-fixture', 'version': '1'},
                'io.modelcontextprotocol/clientCapabilities': USER_VERIFICATION_ONLY_CAPS}}}
            headers = {'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call',
                'Mcp-Name': name, 'Accept': 'application/json, text/event-stream'}
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1') as client:
                    with patch('gateway.subject', return_value='42'):
                        response = await client.post('/mcp', json=payload, headers=headers)
            self.assertEqual(200, response.status_code, response.text)
            return response.json()['result']
        args = {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43, 'script': 'whoami /groups'}
        initial = await post('reach_run_admin', args)
        value = initial['structuredContent']
        self.assertEqual('awaiting_owner_approval', value['state'])
        self.assertNotIn('inputRequests', initial)
        self.assertNotIn('t' * 43, json.dumps(value))
        status_args = {'vm_id': args['vm_id'], 'workflow_token': args['workflow_token'], 'job_id': value['job_id']}
        self.assertEqual(value['approval_url'], (await post('reach_admin_status', status_args))['structuredContent']['approval_url'])
        self.assertEqual(['prepare'], [call['command'] for call in broker.calls])
        await front.portal_decide(value['job_id'], '42', 'once')
        self.assertEqual('completed', (await post('reach_admin_status', status_args))['structuredContent']['state'])
        self.assertEqual(1, len(broker.dispatched))


if __name__ == '__main__':
    unittest.main()
