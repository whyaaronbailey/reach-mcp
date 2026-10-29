"""Actual callback routing and fixed HTTP upstream integration; no live OAuth."""
from contextlib import asynccontextmanager
import unittest
from unittest.mock import patch

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from gateway import OwnerCallbackMux, PREFIX, PUBLIC, RESOURCE, create_app
from test_gateway import FakeChannel, catalog, config


class ProbePortal:
    def __init__(self):
        self.calls = []

    @staticmethod
    def is_portal_state(value):
        return value.startswith('reach-owner-v1.')

    async def handle_callback(self, request):
        values = request.query_params.getlist('state')
        self.calls.append(values)
        return JSONResponse({'portal': True}, status_code=200 if len(values) == 1 else 400)


class CallbackRoutingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.forwarded = []
        self.portal = ProbePortal()

        async def original(scope, receive, send):
            self.forwarded.append((scope['path'], scope['query_string']))
            await JSONResponse({'original': True})(scope, receive, send)

        self.mux = OwnerCallbackMux(original, self.portal)
        app = Starlette(routes=[Route(PREFIX+'/auth/callback', self.mux, methods=['GET'])])
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PUBLIC)

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_existing_mcp_callback_passes_through_without_portal_authentication(self):
        response = await self.client.get(PREFIX+'/auth/callback?code=opaque&state=existing-mcp-state')
        self.assertEqual({'original': True}, response.json())
        self.assertEqual('/auth/callback', self.forwarded[0][0])
        self.assertFalse(self.portal.calls)

    async def test_reserved_browser_callback_reaches_portal_without_original_oauth(self):
        response = await self.client.get(PREFIX+'/auth/callback?state=reach-owner-v1.pending&code=opaque')
        self.assertEqual({'portal': True}, response.json())
        self.assertEqual([['reach-owner-v1.pending']], self.portal.calls)
        self.assertFalse(self.forwarded)

    async def test_duplicate_or_mixed_reserved_state_never_falls_through(self):
        for query in ('state=normal&state=reach-owner-v1.pending',
                      'state=reach-owner-v1.pending&state=normal'):
            response = await self.client.get(PREFIX+'/auth/callback?'+query)
            self.assertEqual(400, response.status_code)
        self.assertEqual(2, len(self.portal.calls))
        self.assertFalse(self.forwarded)

    async def test_encoded_callback_path_is_refused_before_any_handler(self):
        path = (PREFIX+'/auth/callback').replace('/auth/callback', '/%61uth/callback', 1)
        response = await self.client.get(path+'?state=reach-owner-v1.pending')
        self.assertEqual(404, response.status_code)
        self.assertFalse(self.portal.calls)
        self.assertFalse(self.forwarded)

    async def test_missing_state_still_belongs_to_original_mcp_callback(self):
        response = await self.client.get(PREFIX+'/auth/callback')
        self.assertEqual({'original': True}, response.json())
        self.assertFalse(self.portal.calls)


class ConfiguredUpstreamTests(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def client_fixture(self):
        self.channel = FakeChannel()
        app = create_app(config(), self.channel, catalog())

        async def http_upstream(scope, receive, send):
            # Mimic the verified TLS frontend: browser HTTPS, fixed loopback HTTP ASGI.
            await app({**scope, 'scheme': 'http'}, receive, send)

        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=http_upstream),
                    base_url=PUBLIC, follow_redirects=False) as client:
                yield client

    async def test_owner_page_uses_fixed_https_login_and_grants_nothing(self):
        async with self.client_fixture() as client:
            response = await client.get('/reach/nexus/admin/'+'1'*32)
            self.assertEqual(303, response.status_code)
            self.assertEqual(PUBLIC+'/reach/nexus/admin/login?pending='+'1'*32,
                             response.headers['location'])
            self.assertEqual("no-store, private", response.headers['cache-control'])
            self.assertFalse(self.channel.calls)

    async def test_browser_login_preserves_existing_github_callback_and_secure_cookie(self):
        async with self.client_fixture() as client:
            response = await client.get('/reach/nexus/admin/login?pending='+'1'*32)
            self.assertEqual(303, response.status_code)
            self.assertTrue(response.headers['location'].startswith('https://github.com/login/oauth/authorize?'))
            self.assertIn('redirect_uri=https%3A%2F%2Freach.example.invalid%2Fauth%2Fcallback%2Freach%2Fnexus%2Fauth%2Fcallback',
                          response.headers['location'])
            cookie = response.headers['set-cookie']
            for flag in ('__Host-ReachOwnerLogin=', 'HttpOnly', 'Secure', 'SameSite=lax', 'Path=/'):
                self.assertIn(flag, cookie)
            self.assertFalse(self.channel.calls)

    async def test_portal_does_not_change_mcp_discovery_or_authentication_requirement(self):
        async with self.client_fixture() as client:
            discovery = await client.get('/.well-known/oauth-authorization-server'+PREFIX)
            self.assertEqual(200, discovery.status_code)
            self.assertEqual(PUBLIC+PREFIX, discovery.json()['issuer'])
            self.assertEqual(401, (await client.post(RESOURCE,
                json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})).status_code)
            self.assertEqual(404, (await client.post('/reach/nexus/admin', json={})).status_code)
            self.assertFalse(self.channel.calls)
