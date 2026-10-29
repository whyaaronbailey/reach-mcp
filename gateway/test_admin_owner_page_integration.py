"""Composed real HTTP MCP/frontend/browser portal with only provider/broker fixtures."""
import asyncio
from contextlib import asynccontextmanager
import json
import re
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Route

from admin_frontend import AdminUnavailable, ReachAdminFrontend, install_form_metadata
from approval_portal import BASE, CALLBACK, PUBLIC, OwnerApprovalPortal
from channel import ChannelDenied
from gateway import ExactEndpoint, RPCGuard, RESOURCE, ReachProvider
from test_admin_frontend import Broker, Registry
from test_admin_approval_transport import OPENAI_CAPS, USER_VERIFICATION_ONLY_CAPS
from test_approval_portal import config
from test_gateway import catalog


class DistinctJobBroker(Broker):
    """Real broker job IDs differ from prepared operation IDs."""
    def __init__(self):
        super().__init__()
        self.workflow_release_verified = False
        self.jobs = {}
        self.polled_jobs = []
        self.lose_reply = False

    async def request(self, value):
        if value['command'] == 'poll':
            job_id = value['job_id']
            if job_id not in self.jobs:
                raise ChannelDenied()
            self.polled_jobs.append(job_id)
            result = await super().request({**value, 'job_id': self.jobs[job_id]})
            return {**result, 'job_id': job_id}
        result = await super().request(value)
        if value['command'] == 'execute':
            job_id = 'f%031x' % len(self.dispatched)
            self.jobs[job_id] = value['operation_id']
            if self.lose_reply:
                raise AdminUnavailable('Fixture response lost after dispatch.')
            return {**result, 'job_id': job_id}
        return result


class ComposedOwnerApproval(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def fixture(self):
        self.now = 100.0
        self.registry = Registry(lambda: self.now)
        self.channel = SimpleNamespace(registry=self.registry, epoch='e' * 32)
        self.broker = DistinctJobBroker()
        self.admin = ReachAdminFrontend(self.channel, self.broker, clock=lambda: self.now, portal_enabled=True)
        self.exchange = AsyncMock(return_value=42)
        self.portal = OwnerApprovalPortal(config(), get_pending=self.admin.portal_get,
            decide_pending=self.admin.portal_decide, exchange_identity=self.exchange,
            clock=lambda: self.now, transport_scheme='http')
        server = FastMCP('composed-owner-page-fixture',
            providers=[ReachProvider(self.channel, catalog(), admin=self.admin)])
        install_form_metadata(server)
        mcp = server.http_app(path='/mcp', stateless_http=True, json_response=True)
        app = Starlette(routes=self.portal.routes() + [Route(CALLBACK, self.portal.handle_callback),
            Route(RESOURCE, ExactEndpoint(RPCGuard(mcp), '/mcp'), methods=['POST'])])
        async def upstream(scope, receive, send):
            # Browser sees HTTPS and correctly sends Secure cookies. The pinned
            # gateway upstream after TLS termination is intentionally HTTP.
            await app({**scope, 'scheme': 'http'}, receive, send)
        async with mcp.router.lifespan_context(mcp):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream),
                    base_url=PUBLIC, follow_redirects=False) as self.client:
                with patch('gateway.subject', return_value='42'):
                    yield

    async def mcp(self, name, arguments, capabilities=USER_VERIFICATION_ONLY_CAPS, **extra):
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name,
            'arguments': arguments, '_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientInfo': {'name': 'phone-fixture', 'version': '1'},
            'io.modelcontextprotocol/clientCapabilities': capabilities}, **extra}}
        headers = {'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call',
            'Mcp-Name': name, 'Accept': 'application/json, text/event-stream'}
        response = await self.client.post(RESOURCE, json=payload, headers=headers)
        self.assertEqual(200, response.status_code, response.text)
        return response.json()['result']

    async def pending(self, script='whoami /groups'):
        result = await self.mcp('reach_run_admin', {'vm_id': 'vm-alpha',
            'workflow_token': 't' * 43, 'script': script, 'timeout_seconds': 30})
        self.assertNotIn('inputRequests', result)
        value = result['structuredContent']
        self.assertEqual('awaiting_owner_approval', value['state'])
        self.assertFalse(value['administrator_permission_granted'])
        self.assertNotIn('t' * 43, json.dumps(value))
        return value['job_id'], value['approval_url']

    async def login(self, request_id):
        redirect = await self.client.get(BASE + request_id)
        self.assertEqual(303, redirect.status_code)
        start = await self.client.get(redirect.headers['location'])
        self.assertEqual(303, start.status_code)
        authorization = urlparse(start.headers['location'])
        self.assertEqual(('https', 'github.com', '/login/oauth/authorize'),
            (authorization.scheme, authorization.netloc, authorization.path))
        query = parse_qs(authorization.query)
        self.assertEqual(['S256'], query['code_challenge_method'])
        self.assertEqual([PUBLIC + CALLBACK], query['redirect_uri'])
        callback = await self.client.get(CALLBACK, params={'state': query['state'][0], 'code': 'fixture-github-code'})
        self.assertEqual(303, callback.status_code, callback.text)
        self.assertEqual(PUBLIC + BASE + request_id, callback.headers['location'])
        self.assertEqual('fixture-github-code', self.exchange.await_args.args[0])
        self.assertEqual(43, len(self.exchange.await_args.args[1]))
        self.assertFalse(self.broker.dispatched)

    async def review(self, request_id, expected_script='whoami /groups'):
        response = await self.client.get(BASE + request_id)
        self.assertEqual(200, response.status_code, response.text)
        self.assertIn(expected_script, response.text)
        self.assertNotIn('t' * 43, response.text)
        self.assertNotIn('approval_nonce', response.text)
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]{43})"', response.text).group(1)
        return csrf

    async def post(self, request_id, csrf, choice='once'):
        return await self.client.post(BASE + request_id, data={'csrf': csrf, 'choice': choice},
            headers={'Origin': PUBLIC})

    async def status(self, request_id):
        return await self.mcp('reach_admin_status', {'vm_id': 'vm-alpha',
            'workflow_token': 't' * 43, 'job_id': request_id})

    async def test_owner_oauth_exact_review_post_and_same_pending_id_resolves_broker_job(self):
        async with self.fixture():
            request_id, url = await self.pending()
            self.assertEqual(PUBLIC + BASE + request_id, url)
            self.assertEqual('awaiting_owner_approval', (await self.status(request_id))['structuredContent']['state'])
            await self.login(request_id)
            csrf = await self.review(request_id)
            self.assertFalse(self.broker.dispatched)
            response = await self.post(request_id, csrf)
            self.assertEqual(200, response.status_code, response.text)
            self.assertEqual(1, len(self.broker.dispatched))
            self.assertEqual('Reach owner page:' + request_id, self.broker.dispatched[0]['approval_reference'])
            result = (await self.status(request_id))['structuredContent']
            self.assertEqual('completed', result['state'])
            self.assertEqual(request_id, result['approval_request_id'])
            self.assertNotEqual(self.broker.dispatched[0]['operation_id'], result['job_id'])
            self.assertEqual([result['job_id']], self.broker.polled_jobs)
            self.assertEqual(409, (await self.post(request_id, csrf)).status_code)
            self.assertEqual(1, len(self.broker.dispatched))
            # Existing browser identity can approve another exact operation;
            # approval is still explicitly required for that second operation.
            second, _ = await self.pending('whoami /user')
            csrf2 = await self.review(second, 'whoami /user')
            self.assertEqual(1, len(self.broker.dispatched))
            self.assertEqual(200, (await self.post(second, csrf2)).status_code)
            self.assertEqual('completed', (await self.status(second))['structuredContent']['state'])
            self.assertEqual(2, len(self.broker.dispatched))
            self.assertEqual(1, self.exchange.await_count)
            self.assertFalse(self.broker.grants)

    async def test_deny_and_browser_bearer_are_not_administrator_permission(self):
        async with self.fixture():
            request_id, _ = await self.pending()
            response = await self.client.post(BASE + request_id,
                data={'csrf': 'x' * 43, 'choice': 'once'},
                headers={'Origin': PUBLIC, 'Authorization': 'Bearer fixture-mcp-bearer'})
            self.assertEqual(403, response.status_code)
            await self.login(request_id)
            csrf = await self.review(request_id)
            self.assertEqual(200, (await self.post(request_id, csrf, 'deny')).status_code)
            self.assertEqual('declined', (await self.status(request_id))['structuredContent']['state'])
            self.assertEqual(409, (await self.post(request_id, csrf)).status_code)
            self.assertFalse(self.broker.dispatched)

    async def test_release_expiry_and_stale_generation_refuse_owner_post(self):
        async with self.fixture():
            request_id, _ = await self.pending()
            await self.login(request_id)
            csrf = await self.review(request_id)
            await self.admin.end(self.admin.binding('42', {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43}))
            self.assertEqual(409, (await self.post(request_id, csrf)).status_code)
            stale, _ = await self.pending()
            csrf2 = await self.review(stale)
            self.registry.control_id = 'd' * 32
            self.assertEqual(409, (await self.post(stale, csrf2)).status_code)
            self.registry.control_id = 'c' * 32
            expired, _ = await self.pending()
            csrf3 = await self.review(expired)
            self.now = 501
            self.assertEqual(409, (await self.post(expired, csrf3)).status_code)
            self.assertTrue((await self.status(expired)).get('isError'))
            self.assertFalse(self.broker.dispatched)

    async def test_concurrent_owner_posts_and_replay_submit_once(self):
        async with self.fixture():
            request_id, _ = await self.pending()
            await self.login(request_id)
            first = await self.review(request_id)
            second = await self.review(request_id)
            responses = await asyncio.gather(self.post(request_id, first), self.post(request_id, second))
            self.assertEqual([200, 409], sorted(response.status_code for response in responses))
            self.assertEqual(1, len(self.broker.dispatched))
            self.assertEqual('completed', (await self.status(request_id))['structuredContent']['state'])

    async def test_uncertain_callback_never_repeats_administrator_execution(self):
        async with self.fixture():
            request_id, _ = await self.pending()
            await self.login(request_id)
            csrf = await self.review(request_id)
            self.broker.lose_reply = True
            response = await self.post(request_id, csrf)
            self.assertEqual(202, response.status_code)
            self.assertIn('may have started', response.text)
            self.assertEqual('outcome_uncertain', (await self.status(request_id))['structuredContent']['state'])
            self.assertEqual(409, (await self.post(request_id, csrf)).status_code)
            self.assertEqual('outcome_uncertain', (await self.admin.portal_decide(request_id, '42', 'once'))['state'])
            self.assertEqual(1, len(self.broker.dispatched))

    async def test_public_admin_revoke_invalidates_reviewed_owner_form(self):
        async with self.fixture():
            request_id, _ = await self.pending()
            await self.login(request_id)
            csrf = await self.review(request_id)
            revoked = await self.mcp('reach_revoke_admin', {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43})
            self.assertFalse(revoked.get('isError', False))
            self.assertEqual(409, (await self.post(request_id, csrf)).status_code)
            self.assertEqual('revoked', (await self.status(request_id))['structuredContent']['state'])
            self.assertFalse(self.broker.dispatched)

    async def test_sdk_empty_native_accept_transfers_same_operation_to_owner_browser(self):
        async with self.fixture():
            args = {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43,
                'script': 'whoami /groups', 'timeout_seconds': 30}
            first = await self.mcp('reach_run_admin', args, capabilities=OPENAI_CAPS)
            self.assertEqual('input_required', first['resultType'])
            self.assertIn('_meta', first['inputRequests']['owner_admin']['params'])
            second = await self.mcp('reach_run_admin', args, capabilities=OPENAI_CAPS,
                requestState=first['requestState'], inputResponses={'owner_admin': {'action': 'accept', 'content': {}}})
            pending = second['structuredContent']
            self.assertEqual('awaiting_owner_approval', pending['state'])
            self.assertFalse(pending['administrator_permission_granted'])
            self.assertEqual(['prepare'], [call['command'] for call in self.broker.calls])
            self.assertFalse(self.broker.dispatched)
            replay = await self.mcp('reach_run_admin', args, capabilities=OPENAI_CAPS,
                requestState=first['requestState'], inputResponses={'owner_admin': {'action': 'accept', 'content': {'choice': 'once'}}})
            self.assertTrue(replay['isError'])
            await self.login(pending['job_id'])
            csrf = await self.review(pending['job_id'])
            self.assertFalse(self.broker.dispatched)
            self.assertEqual(200, (await self.post(pending['job_id'], csrf)).status_code)
            self.assertEqual('completed', (await self.status(pending['job_id']))['structuredContent']['state'])
            self.assertEqual(1, sum(call['command'] == 'prepare' for call in self.broker.calls))
            self.assertEqual(1, len(self.broker.dispatched))


if __name__ == '__main__':
    unittest.main()
