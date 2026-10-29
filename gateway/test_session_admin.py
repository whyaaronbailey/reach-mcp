"""Session controls exercise authenticated HTTP; all identities and grants are synthetic."""
import copy
import re
import tempfile
import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import httpx
from starlette.applications import Starlette
from starlette.routing import Route

from approval_portal import SessionApprovalPortal, PUBLIC, BASE, CALLBACK, OWNER_COOKIE
from test_approval_portal import config, PENDING


class SessionBrowserTests(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def fixture(self):
        self.now = 1000.0
        self.view = {'state':'awaiting_owner','vm_id':'vm-beta','script':'whoami /groups',
            'arguments':[],'timeout_seconds':60,'request_sha256':'f'*64,'expires_at':1500.,
            'session_allowed':True,'session_id':'c'*32}
        self.rows = [{'scope':'b'*64,'session_id':'c'*32,'vm_id':'vm-beta',
            'permission_mode':'workflow','verified':True,'ended':False,'expires_at':1500.,'jobs_in_progress':1}]
        self.list = AsyncMock(side_effect=lambda owner: {'ok':True,'sessions':copy.deepcopy(self.rows)})
        self.revoke = AsyncMock(return_value={'ok':True,'durable_reduction_accepted':True})
        self.decide = AsyncMock(side_effect=lambda rid,owner,choice: {'ok':True,'state':'running',
            'administrator_permission_granted':True,'permission_mode':'workflow' if choice=='workflow' else 'once'})
        with tempfile.TemporaryDirectory() as root:
            self.portal = SessionApprovalPortal(config(), get_pending=AsyncMock(side_effect=lambda *_:copy.deepcopy(self.view)),
                decide_pending=self.decide, list_sessions=self.list, revoke_sessions=self.revoke,
                exchange_identity=AsyncMock(return_value=42), clock=lambda:self.now, push_root=root)
            app = Starlette(routes=self.portal.routes()+[Route(CALLBACK,self.portal.handle_callback)])
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url=PUBLIC) as self.client:
                yield

    async def login(self):
        start = await self.client.get(BASE+'login?pending=home')
        state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
        self.assertEqual(303,(await self.client.get(CALLBACK,params={'state':state,'code':'synthetic-code'})).status_code)

    async def forms(self):
        response = await self.client.get(BASE)
        self.assertEqual(200,response.status_code)
        forms = re.findall(r'<input type="hidden" name="csrf" value="([A-Za-z0-9_-]{43})"><input type="hidden" name="scope" value="([a-f0-9]{64}|all)">',response.text)
        return {scope:csrf for csrf,scope in forms}, response.text

    async def submit(self, csrf, scope, **kwargs):
        return await self.client.post(BASE+'sessions/revoke',data={'csrf':csrf,'scope':scope},
            headers=kwargs.pop('headers',{'Origin':PUBLIC}),**kwargs)

    async def test_home_requires_owner_identity_and_get_never_reduces_or_grants(self):
        async with self.fixture():
            response = await self.client.get(BASE)
            self.assertNotIn('Session permission active',response.text)
            self.list.assert_not_awaited()
            await self.login()
            forms,text = await self.forms()
            self.assertEqual({'all','b'*64},set(forms))
            self.assertIn('Session permission active',text)
            self.assertIn('1 command(s) in progress',text)
            self.revoke.assert_not_awaited();self.decide.assert_not_awaited()

    async def test_single_session_revoke_is_owner_bound_and_consumed_once(self):
        async with self.fixture():
            await self.login();forms,_ = await self.forms()
            self.assertEqual(200,(await self.submit(forms['b'*64],'b'*64)).status_code)
            self.revoke.assert_awaited_once_with('42','b'*64)
            self.assertEqual(409,(await self.submit(forms['b'*64],'b'*64)).status_code)

    async def test_revoke_all_has_its_own_exact_scope(self):
        async with self.fixture():
            await self.login();forms,_ = await self.forms()
            self.assertEqual(409,(await self.submit(forms['b'*64],'all')).status_code)
            self.revoke.assert_not_awaited()
            self.assertEqual(200,(await self.submit(forms['all'],'all')).status_code)
            self.revoke.assert_awaited_once_with('42','all')

    async def test_cross_origin_and_missing_identity_cannot_revoke(self):
        async with self.fixture():
            await self.login();forms,_ = await self.forms()
            for headers in ({},{'Origin':'https://example.invalid'}, {'Origin':PUBLIC,'Sec-Fetch-Site':'cross-site'}):
                self.assertEqual(403,(await self.submit(forms['all'],'all',headers=headers)).status_code)
            self.client.cookies.clear()
            self.assertEqual(403,(await self.submit(forms['all'],'all')).status_code)
            self.revoke.assert_not_awaited()

    async def test_expired_or_other_browser_form_cannot_revoke(self):
        async with self.fixture():
            await self.login();forms,_ = await self.forms()
            self.client.cookies.clear();await self.login()
            self.assertEqual(409,(await self.submit(forms['all'],'all')).status_code)
            forms,_ = await self.forms();self.now += 301
            self.assertEqual(409,(await self.submit(forms['all'],'all')).status_code)
            self.revoke.assert_not_awaited()

    async def test_duplicate_fields_and_oversized_body_refused(self):
        async with self.fixture():
            await self.login();forms,_ = await self.forms()
            headers={'Origin':PUBLIC,'Content-Type':'application/x-www-form-urlencoded'}
            data='csrf='+forms['all']+'&scope=all&scope='+'b'*64
            self.assertEqual(400,(await self.client.post(BASE+'sessions/revoke',content=data,headers=headers)).status_code)
            self.assertEqual(413,(await self.client.post(BASE+'sessions/revoke',content='x'*4097,headers=headers)).status_code)
            self.revoke.assert_not_awaited()

    async def test_broker_failure_is_not_reported_as_revoked(self):
        async with self.fixture():
            await self.login();forms,_ = await self.forms();self.revoke.side_effect = RuntimeError('synthetic unavailable')
            response = await self.submit(forms['all'],'all')
            self.assertEqual(503,response.status_code)
            self.assertIn('Revocation not confirmed',response.text)
            self.assertEqual(409,(await self.submit(forms['all'],'all')).status_code)
            self.decide.assert_not_awaited()

    async def test_unknown_session_data_never_becomes_an_active_grant(self):
        async with self.fixture():
            await self.login();self.rows[0]['verified'] = False
            _,text = await self.forms()
            self.assertIn('Verification unavailable',text);self.assertNotIn('Session permission active',text)
            self.rows[0]['vm_id'] = '<script>bad()</script>'
            _,text = await self.forms();self.assertIn('status is unavailable',text);self.assertNotIn('<script>bad()',text)

    async def test_session_choice_is_offered_and_recorded_only_by_authenticated_post(self):
        async with self.fixture():
            await self.login();response = await self.client.get(BASE+PENDING)
            self.assertIn('Allow for this Reach session',response.text)
            csrf = re.search('name="csrf" value="([A-Za-z0-9_-]{43})"',response.text)[1]
            self.decide.assert_not_awaited()
            response = await self.client.post(BASE+PENDING,data={'csrf':csrf,'choice':'workflow'},headers={'Origin':PUBLIC})
            self.assertEqual(200,response.status_code);self.assertIn('Reach session approved',response.text)
            self.decide.assert_awaited_once_with(PENDING,'42','workflow')

    async def test_session_choice_needs_verified_offer_on_both_get_and_post(self):
        async with self.fixture():
            await self.login();self.view['session_allowed'] = False
            response = await self.client.get(BASE+PENDING)
            self.assertNotIn('Allow for this Reach session',response.text)
            csrf = re.search('name="csrf" value="([A-Za-z0-9_-]{43})"',response.text)[1]
            self.view['session_allowed'] = True
            self.assertEqual(409,(await self.client.post(BASE+PENDING,data={'csrf':csrf,'choice':'workflow'},headers={'Origin':PUBLIC})).status_code)
            self.decide.assert_not_awaited()
            response = await self.client.get(BASE+PENDING)
            csrf = re.search('name="csrf" value="([A-Za-z0-9_-]{43})"',response.text)[1]
            self.view['session_allowed'] = False
            self.assertEqual(409,(await self.client.post(BASE+PENDING,data={'csrf':csrf,'choice':'workflow'},headers={'Origin':PUBLIC})).status_code)
            self.decide.assert_not_awaited()
