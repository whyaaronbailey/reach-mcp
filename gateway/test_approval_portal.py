"""Browser approval boundary tests; fixtures are not phone or deployment acceptance."""
import asyncio
from contextlib import asynccontextmanager
import copy
import re
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
from starlette.applications import Starlette
from starlette.routing import Route

from approval_portal import (OwnerApprovalPortal, PUBLIC, CALLBACK, BASE, STATE_PREFIX,
                             OWNER_COOKIE, LOGIN_COOKIE, GITHUB_ISSUER, CallbackLog,
                             owned_cookies, is_portal_state)

PENDING = 'a'*32


def config():
    return {'oauth_config':{'public_url':PUBLIC, 'client_id':'fixture-client-identifier',
        'client_secret':'fixture-client-secret-only', 'allowed_github_user_ids':[42],
        'owner_approval_oauth':{'client_id':'fixture-owner-portal-client-id',
            'client_secret':'fixture-owner-portal-client-secret'}},
        'oauth_key':'fixture-independent-existing-key'}


class BrowserApproval(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def fixture(self, owner=42):
        self.now = 1000.0
        self.view = {'state':'awaiting_owner', 'vm_id':'vm-beta',
            'script':'Write-Output "</pre><script>alert(1)</script>"',
            'arguments':['<img src=x onerror=bad>','two words'], 'timeout_seconds':60,
            'request_sha256':'f'*64, 'expires_at':1600.0}
        self.read = AsyncMock(side_effect=lambda pending_id, identity: copy.deepcopy(self.view))
        self.decide = AsyncMock(side_effect=lambda pending_id,owner,choice: {'ok':True,
            'state':'declined' if choice=='deny' else 'running', 'job_id':'b'*32,
            'administrator_permission_granted':choice=='once'})
        self.exchange = AsyncMock(return_value=owner)
        self.portal = OwnerApprovalPortal(config(), get_pending=self.read, decide_pending=self.decide,
            exchange_identity=self.exchange, clock=lambda:self.now)
        app = Starlette(routes=self.portal.routes()+[Route(CALLBACK, self.portal.handle_callback)])
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url=PUBLIC, follow_redirects=False) as self.client:
            yield

    async def login_start(self):
        response = await self.client.get(BASE+'login', params={'pending':PENDING})
        self.assertEqual(303, response.status_code)
        location = urlparse(response.headers['location'])
        self.assertEqual(('https','github.com','/login/oauth/authorize'),
                         (location.scheme,location.netloc,location.path))
        query = parse_qs(location.query)
        self.assertEqual([config()['oauth_config']['owner_approval_oauth']['client_id']],query['client_id'])
        self.assertEqual([PUBLIC+CALLBACK], query['redirect_uri'])
        self.assertEqual(['S256'], query['code_challenge_method'])
        return query['state'][0]

    async def authenticate(self):
        state = await self.login_start()
        response = await self.client.get(CALLBACK, params={'state':state, 'code':'provider-code'})
        self.assertEqual(303, response.status_code)
        self.assertEqual(PUBLIC+BASE+PENDING, response.headers['location'])
        return response

    async def review_form(self, pending_id=PENDING):
        response = await self.client.get(BASE+pending_id)
        self.assertEqual(200, response.status_code)
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]{43})"', response.text).group(1)
        return csrf, response

    async def submit(self, csrf, choice='once', pending_id=PENDING, **kwargs):
        return await self.client.post(BASE+pending_id, data={'csrf':csrf,'choice':choice},
            headers=kwargs.pop('headers', {'Origin':PUBLIC}), **kwargs)

    async def test_url_and_get_callback_never_approve(self):
        async with self.fixture():
            r = await self.client.get(BASE+PENDING)
            self.assertEqual(303,r.status_code)
            self.assertFalse(self.read.called)
            response = await self.authenticate()
            self.assertFalse(self.decide.called)
            self.assertFalse(self.read.called)
            cookie = response.headers['set-cookie']
            for value in ('HttpOnly','Secure','SameSite=lax','Path=/'):
                self.assertIn(value,cookie)
            self.assertNotIn('Domain=',cookie)
            self.assertEqual(1,self.exchange.await_count)
            self.assertEqual('provider-code',self.exchange.await_args.args[0])
            self.assertEqual(43,len(self.exchange.await_args.args[1]))

    async def test_exact_escaped_review_and_one_use_approval(self):
        async with self.fixture():
            await self.authenticate()
            csrf,r = await self.review_form()
            self.assertIn('&lt;script&gt;',r.text)
            self.assertNotIn('<script>',r.text)
            self.assertNotIn('<img',r.text)
            self.assertIn('f'*64,r.text)
            self.assertIn('60',r.text)
            self.assertIn('two words',r.text)
            self.assertIn("frame-ancestors 'none'",r.headers['content-security-policy'])
            self.assertEqual('same-origin',r.headers['referrer-policy'])
            self.assertEqual(200,(await self.submit(csrf)).status_code)
            self.decide.assert_awaited_once_with(PENDING,'42','once')
            self.assertEqual(409,(await self.submit(csrf)).status_code)
            self.assertEqual(409,(await self.client.get(BASE+PENDING)).status_code)

    async def test_explicit_deny_only_calls_deny(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_ = await self.review_form()
            response=await self.submit(csrf,'deny')
            self.assertEqual(200,response.status_code)
            self.assertIn('Reach operation denied',response.text)
            self.assertNotIn('Reach operation approved once',response.text)
            self.decide.assert_awaited_once_with(PENDING,'42','deny')

    async def test_wrong_owner_cannot_create_browser_session(self):
        async with self.fixture(owner=43):
            state = await self.login_start()
            self.assertEqual(403,(await self.client.get(CALLBACK,
                params={'state':state,'code':'provider-code'})).status_code)
            self.assertFalse(self.client.cookies.get(OWNER_COOKIE))
            self.assertFalse(self.decide.called)

    async def test_state_cookie_binding_checked_before_exchange(self):
        async with self.fixture():
            state = await self.login_start()
            self.client.cookies.clear()
            self.assertEqual(403,(await self.client.get(CALLBACK,
                params={'state':state,'code':'provider-code'})).status_code)
            self.exchange.assert_not_awaited()
            self.assertFalse(self.decide.called)

    async def test_expired_unknown_duplicate_and_replayed_state(self):
        async with self.fixture():
            state = await self.login_start()
            for pairs in ([('state',state),('state',state),('code','x')],
                          [('state',STATE_PREFIX+'z'*43),('code','x')]):
                self.assertIn((await self.client.get(CALLBACK,params=pairs)).status_code,(400,403))
            self.exchange.assert_not_awaited()
            self.now += 301
            self.assertEqual(403,(await self.client.get(CALLBACK,params={'state':state,'code':'x'})).status_code)
            self.exchange.assert_not_awaited()
            self.now = 1000
            state = await self.login_start()
            self.assertEqual(303,(await self.client.get(CALLBACK,params={'state':state,'code':'x'})).status_code)
            self.assertEqual(403,(await self.client.get(CALLBACK,params={'state':state,'code':'x'})).status_code)
            self.assertEqual(1,self.exchange.await_count)

    async def test_post_requires_browser_identity_not_mcp_bearer(self):
        async with self.fixture():
            r=await self.client.post(BASE+PENDING,data={'csrf':'x'*43,'choice':'once'},
                headers={'Origin':PUBLIC,'Authorization':'Bearer arbitrary-mcp-token'})
            self.assertEqual(403,r.status_code)
            self.decide.assert_not_awaited()

    async def test_origin_csrf_and_exact_choice_required(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_=await self.review_form()
            for headers in ({},{'Origin':'https://evil.invalid'},
                            {'Origin':PUBLIC,'Sec-Fetch-Site':'cross-site'}):
                self.assertEqual(403,(await self.submit(csrf,headers=headers)).status_code)
            self.assertEqual(409,(await self.submit('z'*43)).status_code)
            for data in ({'csrf':csrf},{'csrf':csrf,'choice':'unknown'},
                         {'csrf':csrf,'choice':'once','extra':'yes'}):
                self.assertEqual(400,(await self.client.post(BASE+PENDING,data=data,
                    headers={'Origin':PUBLIC})).status_code)
            duplicate='csrf='+csrf+'&choice=once&choice=deny'
            self.assertEqual(400,(await self.client.post(BASE+PENDING,content=duplicate,
                headers={'Origin':PUBLIC,'Content-Type':'application/x-www-form-urlencoded'})).status_code)
            self.decide.assert_not_awaited()

    async def test_generated_form_preserves_origin_and_null_origin_never_approves(self):
        # Fetch's append-a-request-Origin algorithm converts non-CORS POST Origin
        # to null under no-referrer. Keep the form usable without accepting null.
        async with self.fixture():
            await self.authenticate()
            csrf,response=await self.review_form()
            self.assertEqual('same-origin',response.headers['referrer-policy'])
            self.assertEqual(403,(await self.submit(csrf,headers={'Origin':'null'})).status_code)
            self.decide.assert_not_awaited()
            self.assertEqual(200,(await self.submit(csrf,headers={'Origin':PUBLIC})).status_code)
            self.decide.assert_awaited_once_with(PENDING,'42','once')

    async def test_singleton_origin_and_content_type_headers_required(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_=await self.review_form()
            content='csrf='+csrf+'&choice=once'
            for headers in ([('Origin',PUBLIC),('Origin',PUBLIC),('Content-Type','application/x-www-form-urlencoded')],
                            [('Origin',PUBLIC),('Content-Type','application/x-www-form-urlencoded'),
                             ('Content-Type','application/x-www-form-urlencoded')]):
                self.assertEqual(403,(await self.client.post(BASE+PENDING,content=content,headers=headers)).status_code)
            self.decide.assert_not_awaited()

    async def test_frontend_argument_byte_limits_and_mobile_review(self):
        async with self.fixture():
            await self.authenticate()
            self.view['arguments']=['é'*4096]*4
            csrf,r=await self.review_form()
            self.assertIn('min-height:48px',r.text)
            self.assertIn('style-src \'sha256-',r.headers['content-security-policy'])
            self.assertNotIn("'unsafe-inline'",r.headers['content-security-policy'])
            self.assertLess(r.text.index('PowerShell script'),r.text.index('<summary>Verification'))
            self.assertEqual(200,(await self.submit(csrf)).status_code)
            self.view['arguments']=['é'*4097]
            self.assertEqual(404,(await self.client.get(BASE+PENDING)).status_code)
            self.view['arguments']=['x'*8192]*4+['x']
            self.assertEqual(404,(await self.client.get(BASE+PENDING)).status_code)

    async def test_returned_refusal_and_uncertainty_are_not_reported_as_success(self):
        for state,approved,status in [('revoked',False,409),('outcome_uncertain',True,202),
                                      ('dispatching',True,202)]:
            async with self.fixture():
                await self.authenticate()
                csrf,_=await self.review_form()
                self.decide.side_effect=None
                self.decide.return_value={'ok':True,'state':state,'administrator_permission_granted':approved}
                response=await self.submit(csrf)
                self.assertEqual(status,response.status_code)
                self.assertNotIn('Reach operation approved once',response.text)

    async def test_stale_hash_expiry_release_and_revoke_never_dispatch(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_=await self.review_form()
            self.view['request_sha256']='e'*64
            self.assertEqual(409,(await self.submit(csrf)).status_code)
            self.view['expires_at']=self.now
            self.assertEqual(409,(await self.submit(csrf)).status_code)
            self.view['expires_at']=1600
            for state in ('released','revoked','expired','uncertain'):
                self.view['state']=state
                self.assertEqual(409,(await self.submit(csrf)).status_code)
            self.decide.assert_not_awaited()

    async def test_frontend_binding_failure_refuses_review_and_submit(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_=await self.review_form()
            self.read.side_effect=RuntimeError('secret binding information')
            r=await self.submit(csrf)
            self.assertEqual(409,r.status_code)
            self.assertNotIn('secret',r.text)
            self.assertEqual(404,(await self.client.get(BASE+PENDING)).status_code)
            self.decide.assert_not_awaited()

    async def test_callback_uncertainty_consumed_never_retried(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_=await self.review_form()
            self.decide.side_effect=RuntimeError('private dispatch detail')
            r=await self.submit(csrf)
            self.assertEqual(503,r.status_code)
            self.assertNotIn('private dispatch detail',r.text)
            self.assertEqual(409,(await self.submit(csrf)).status_code)
            self.assertEqual(1,self.decide.await_count)

    async def test_concurrent_posts_invoke_callback_exactly_once(self):
        async with self.fixture():
            await self.authenticate()
            first,_=await self.review_form()
            second,_=await self.review_form()
            results=await asyncio.gather(self.submit(first),self.submit(second))
            self.assertEqual([200,409],sorted(r.status_code for r in results))
            self.assertEqual(1,self.decide.await_count)

    async def test_restart_invalidates_identity_state_and_form(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_=await self.review_form()
            self.portal.sessions.clear()
            self.portal.logins.clear()
            self.portal.forms.clear()
            self.assertEqual(403,(await self.submit(csrf)).status_code)
            self.assertEqual(303,(await self.client.get(BASE+PENDING)).status_code)
            self.decide.assert_not_awaited()

    async def test_canonical_https_host_path_and_duplicate_cookies_required(self):
        async with self.fixture():
            for url,headers in ((PUBLIC.replace('https:','http:')+BASE+'login?pending='+PENDING,{}),
                                (BASE+'login?pending='+PENDING,{'Host':'evil.invalid'}),
                                (BASE+'%6cogin?pending='+PENDING,{}),
                                (BASE+'login?pending='+PENDING,{'Cookie':LOGIN_COOKIE+'='+'a'*43+'; '+LOGIN_COOKIE+'='+'a'*43})):
                self.assertIn((await self.client.get(url,headers=headers)).status_code,(403,404))
            self.exchange.assert_not_awaited()
            self.decide.assert_not_awaited()

    async def test_wrong_browser_csrf_and_large_body_refuse(self):
        async with self.fixture():
            await self.authenticate()
            csrf,_=await self.review_form()
            self.client.cookies.clear()
            await self.authenticate()
            self.assertEqual(409,(await self.submit(csrf)).status_code)
            self.assertEqual(413,(await self.client.post(BASE+PENDING,content='a'*4097,
                headers={'Origin':PUBLIC,'Content-Type':'application/x-www-form-urlencoded'})).status_code)
            self.decide.assert_not_awaited()

    async def test_github_production_exchange_pins_endpoints_and_owner_id_only(self):
        async with self.fixture():
            calls=[]
            def respond(request):
                calls.append(request)
                if str(request.url)=='https://github.com/login/oauth/access_token':
                    return httpx.Response(200,json={'access_token':'private-provider-token','token_type':'bearer'})
                self.assertEqual('https://api.github.com/user',str(request.url))
                self.assertEqual('Bearer private-provider-token',request.headers['Authorization'])
                return httpx.Response(200,json={'id':42,'login':'untrusted-display-name'})
            real_client=httpx.AsyncClient
            def client(**kwargs):
                self.assertFalse(kwargs['follow_redirects'])
                self.assertFalse(kwargs['trust_env'])
                return real_client(transport=httpx.MockTransport(respond),**kwargs)
            with patch('approval_portal.httpx.AsyncClient',side_effect=client):
                self.assertEqual(42,await self.portal._github_identity('exact-code','exact-verifier'))
            fields=parse_qs(calls[0].content.decode())
            self.assertEqual([config()['oauth_config']['owner_approval_oauth']['client_id']],fields['client_id'])
            self.assertEqual([config()['oauth_config']['owner_approval_oauth']['client_secret']],fields['client_secret'])
            self.assertNotEqual([config()['oauth_config']['client_id']],fields['client_id'])
            self.assertEqual(['exact-verifier'],fields['code_verifier'])
            self.assertEqual([PUBLIC+CALLBACK],fields['redirect_uri'])
            self.assertEqual(2,len(calls))

    async def test_fixed_http_upstream_mode_never_uses_forwarded_headers(self):
        async with self.fixture():
            self.portal.transport_scheme='http'
            r=await self.client.get(PUBLIC.replace('https:','http:')+BASE+'login',
                params={'pending':PENDING}, headers={'X-Forwarded-Proto':'evil'})
            self.assertEqual(303,r.status_code)
            self.assertIn('Secure',r.headers['set-cookie'])
            self.assertEqual(403,(await self.client.get(BASE+'login',params={'pending':PENDING},
                headers={'X-Forwarded-Proto':'http'})).status_code)
            self.assertEqual(403,(await self.client.get(PUBLIC.replace('https:','http:')+BASE+'login',
                params={'pending':PENDING},headers={'Host':'evil.invalid','X-Forwarded-Host':'reach.example.invalid'})).status_code)

    async def real_frontend(self):
        from types import SimpleNamespace
        from admin_frontend import ReachAdminFrontend
        from test_admin_frontend import Broker, Registry
        from test_admin_approval_transport import context, USER_VERIFICATION_ONLY_CAPS
        registry=Registry(lambda:self.now)
        registry.expires_at=1600
        broker=Broker()
        broker.workflow_release_verified=False
        front=ReachAdminFrontend(SimpleNamespace(registry=registry,epoch='e'*32),broker,
                                clock=lambda:self.now,portal_enabled=True)
        self.portal.get_pending=front.portal_get
        self.portal.decide_pending=front.portal_decide
        args={'vm_id':'vm-alpha','workflow_token':'t'*43,'script':'whoami /groups',
              'arguments':[],'timeout_seconds':60}
        result=await front.run('reach_run_admin',args,'42',context(capabilities=USER_VERIFICATION_ONLY_CAPS))
        return front,registry,broker,args,result['job_id']

    async def test_real_frontend_browser_approval_to_original_status_once(self):
        async with self.fixture():
            front,registry,broker,args,pending_id=await self.real_frontend()
            await self.authenticate()
            csrf,_=await self.review_form(pending_id)
            self.assertEqual(['prepare'],[x['command'] for x in broker.calls])
            self.assertEqual(200,(await self.submit(csrf,pending_id=pending_id)).status_code)
            self.assertEqual(1,len(broker.dispatched))
            self.assertEqual('Reach owner page:'+pending_id,broker.dispatched[0]['approval_reference'])
            from test_admin_approval_transport import context
            status=await front.run('reach_admin_status',{'vm_id':args['vm_id'],
                'workflow_token':args['workflow_token'],'job_id':pending_id},'42',context())
            self.assertEqual('completed',status['state'])
            self.assertEqual(pending_id,status['approval_request_id'])
            self.assertEqual(409,(await self.submit(csrf,pending_id=pending_id)).status_code)
            self.assertEqual(1,len(broker.dispatched))
            self.assertFalse(broker.grants)

    async def test_real_frontend_denial_and_changed_binding_never_execute(self):
        async with self.fixture():
            front,registry,broker,args,pending_id=await self.real_frontend()
            await self.authenticate()
            csrf,_=await self.review_form(pending_id)
            self.assertEqual(200,(await self.submit(csrf,'deny',pending_id=pending_id)).status_code)
            self.assertFalse(broker.dispatched)
            front,registry,broker,args,pending_id=await self.real_frontend()
            csrf,_=await self.review_form(pending_id)
            registry.control_id='d'*32
            self.assertEqual(409,(await self.submit(csrf,pending_id=pending_id)).status_code)
            self.assertFalse(broker.dispatched)

    def test_namespace_and_config_fail_closed(self):
        self.assertTrue(is_portal_state(STATE_PREFIX+'malformed'))
        self.assertFalse(is_portal_state('ordinary-fastmcp-state'))
        for cfg in ({}, {'oauth_config':{'public_url':'https://evil.invalid'}},
                    {'oauth_config':{**config()['oauth_config'],'allowed_github_user_ids':[True]}}):
            with self.assertRaises(ValueError):
                OwnerApprovalPortal(cfg,get_pending=AsyncMock(),decide_pending=AsyncMock())
        with self.assertRaises(ValueError):
            OwnerApprovalPortal(config(),get_pending=AsyncMock(),decide_pending=AsyncMock(),
                                transport_scheme='forwarded')

    def test_missing_malformed_or_shared_portal_app_never_falls_back_to_mcp(self):
        for portal_config in (None,{},'shared',{'client_id':'fixture-owner-portal-client-id'},
                              {'client_id':config()['oauth_config']['client_id'],
                               'client_secret':'fixture-owner-portal-client-secret'}):
            cfg=config()
            if portal_config is None:
                del cfg['oauth_config']['owner_approval_oauth']
            else:
                cfg['oauth_config']['owner_approval_oauth']=portal_config
            with self.subTest(portal_config=portal_config),self.assertRaises(ValueError):
                OwnerApprovalPortal(cfg,get_pending=AsyncMock(),decide_pending=AsyncMock())

    async def test_issuer_and_unknown_extensions_with_split_cookies_complete_callback(self):
        async with self.fixture():
            records=[];self.portal.diagnostics=records.append
            state=await self.login_start();cookie=self.client.cookies.get(LOGIN_COOKIE)
            response=await self.client.get(CALLBACK,params={'state':state,'code':'provider-code',
                'iss':GITHUB_ISSUER,'future_extension':'ignored-private-value',
                'owner':'43','redirect_uri':'https://evil.invalid','choice':'once'},headers=[
                    ('Cookie','unraid_session=one; unraid_session=two'),('Cookie',LOGIN_COOKIE+'='+cookie)])
            self.assertEqual(303,response.status_code)
            self.assertEqual(PUBLIC+BASE+PENDING,response.headers['location'])
            self.exchange.assert_awaited_once()
            self.decide.assert_not_awaited()
            self.assertTrue(self.client.cookies.get(OWNER_COOKIE))
            self.assertIn('callback_session_created',[r['stage'] for r in records])
            rendered=__import__('json').dumps(records)
            for secret in (state,cookie,'provider-code','ignored-private-value','evil.invalid',
                           config()['oauth_config']['owner_approval_oauth']['client_secret']):
                self.assertNotIn(secret,rendered)
            self.assertTrue(all(CallbackLog.safe(r) for r in records))

    async def test_wrong_or_duplicate_issuer_refuses_before_exchange(self):
        async with self.fixture():
            state=await self.login_start()
            for issuer in ('https://evil.invalid','http://github.com/login/oauth',GITHUB_ISSUER+'/', ''):
                self.assertEqual(403,(await self.client.get(CALLBACK,
                    params={'state':state,'code':'provider-code','iss':issuer})).status_code)
            duplicate=[('state',state),('code','provider-code'),('iss',GITHUB_ISSUER),('iss',GITHUB_ISSUER)]
            self.assertEqual(400,(await self.client.get(CALLBACK,params=duplicate)).status_code)
            self.exchange.assert_not_awaited();self.decide.assert_not_awaited()
            self.assertEqual(303,(await self.client.get(CALLBACK,
                params={'state':state,'code':'provider-code','iss':GITHUB_ISSUER})).status_code)

    async def test_unknown_parameters_cannot_override_error_or_owner(self):
        async with self.fixture(owner=43):
            state=await self.login_start()
            self.assertEqual(403,(await self.client.get(CALLBACK,params={'state':state,'code':'provider-code',
                'iss':GITHUB_ISSUER,'error':'access_denied','choice':'once'})).status_code)
            self.exchange.assert_not_awaited()
            self.assertEqual(403,(await self.client.get(CALLBACK,params={'state':state,'code':'provider-code',
                'iss':GITHUB_ISSUER,'owner':'42'})).status_code)
            self.assertFalse(self.client.cookies.get(OWNER_COOKIE));self.decide.assert_not_awaited()

    async def test_duplicate_unknown_parameter_still_refuses(self):
        async with self.fixture():
            state=await self.login_start()
            pairs=[('state',state),('code','provider-code'),('iss',GITHUB_ISSUER),('future','one'),('future','two')]
            self.assertEqual(400,(await self.client.get(CALLBACK,params=pairs)).status_code)
            self.exchange.assert_not_awaited();self.decide.assert_not_awaited()

    async def test_duplicate_owned_cookie_across_fields_never_exchanges(self):
        async with self.fixture():
            state=await self.login_start();cookie=self.client.cookies.get(LOGIN_COOKIE)
            for headers in ([('Cookie',LOGIN_COOKIE+'='+cookie),('Cookie',LOGIN_COOKIE+'='+cookie)],
                            [('Cookie',LOGIN_COOKIE+'='+cookie+'; '+LOGIN_COOKIE+'='+cookie)]):
                self.assertEqual(403,(await self.client.get(CALLBACK,
                    params={'state':state,'code':'provider-code','iss':GITHUB_ISSUER},headers=headers)).status_code)
            self.exchange.assert_not_awaited();self.decide.assert_not_awaited()

    async def test_split_browser_session_cookie_still_requires_exact_csrf_origin(self):
        async with self.fixture():
            await self.authenticate();cookie=self.client.cookies.get(OWNER_COOKIE)
            headers=[('Cookie','unrelated=one; unrelated=two'),('Cookie',OWNER_COOKIE+'='+cookie)]
            response=await self.client.get(BASE+PENDING,headers=headers)
            self.assertEqual(200,response.status_code)
            csrf=re.search(r'name="csrf" value="([A-Za-z0-9_-]{43})"',response.text).group(1)
            self.assertEqual(403,(await self.submit(csrf,headers=headers+[('Origin','null')])).status_code)
            self.decide.assert_not_awaited()
            self.assertEqual(200,(await self.submit(csrf,headers=headers+[('Origin',PUBLIC)])).status_code)
            self.decide.assert_awaited_once_with(PENDING,'42','once')

    async def test_private_diagnostics_failure_cannot_change_authentication(self):
        async with self.fixture():
            def unavailable(record):raise RuntimeError('private logging failure')
            self.portal.diagnostics=unavailable
            await self.authenticate()
            self.assertTrue(self.client.cookies.get(OWNER_COOKIE));self.decide.assert_not_awaited()

    def test_owned_cookie_parser_is_bounded_and_diagnostics_accept_no_values(self):
        self.assertEqual({LOGIN_COOKIE:'a'*43},owned_cookies(['other=one; other=two',LOGIN_COOKIE+'='+'a'*43])[0])
        self.assertIsNone(owned_cookies([LOGIN_COOKIE+'='+'a'*43,LOGIN_COOKIE+'='+'b'*43])[0])
        for raw in (LOGIN_COOKIE+'=short',LOGIN_COOKIE+'="'+'a'*43+'"','bad\rheader=x','x'*16385):
            self.assertIsNone(owned_cookies([raw])[0])
        for record in ({'stage':'callback_received','code':'private'},
                       {'stage':'callback_received','query_count':'private'},
                       {'stage':'arbitrary-private-value'},
                       {'stage':'callback_received','query_count':-1}):
            self.assertFalse(CallbackLog.safe(record))
        self.assertFalse(CallbackLog.safe({'stage':['private']}))

    def test_private_log_writes_only_allowlisted_metadata_at_private_mode(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        import os,stat
        fake=SimpleNamespace(name='posix',path=SimpleNamespace(dirname=os.path.dirname,lexists=lambda p:False),
            makedirs=Mock(),stat=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=10008)),
            geteuid=lambda:10008,open=Mock(return_value=17),fstat=Mock(return_value=SimpleNamespace(
                st_mode=stat.S_IFREG|0o600,st_uid=10008,st_nlink=1)),write=Mock(),close=Mock(),
            O_WRONLY=os.O_WRONLY,O_APPEND=os.O_APPEND,O_CREAT=os.O_CREAT,O_NOFOLLOW=0)
        with patch('approval_portal.os',fake):
            log=CallbackLog('/private/owner-portal.jsonl')
            log({'stage':'callback_received','cookie_header_count':2,'cookie_parse_ok':True})
            self.assertEqual(0o600,fake.open.call_args.args[2])
            value=__import__('json').loads(fake.write.call_args.args[1])
            self.assertEqual({'utc','stage','cookie_header_count','cookie_parse_ok'},set(value))
            self.assertLess(len(fake.write.call_args.args[1]),4096)
            fake.close.assert_called_once_with(17)
            fake.write.reset_mock()
            log({'stage':'callback_received','code':'never-log-code'})
            fake.write.assert_not_called()

    def test_private_log_refuses_nonprivate_file_or_directory(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        import os,stat
        for directory_mode,file_mode in ((0o755,0o600),(0o700,0o644)):
            fake=SimpleNamespace(name='posix',path=SimpleNamespace(dirname=os.path.dirname,lexists=lambda p:False),
                makedirs=Mock(),stat=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFDIR|directory_mode,st_uid=10008)),
                geteuid=lambda:10008,open=Mock(return_value=17),fstat=Mock(return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG|file_mode,st_uid=10008,st_nlink=1)),write=Mock(),close=Mock(),
                O_WRONLY=os.O_WRONLY,O_APPEND=os.O_APPEND,O_CREAT=os.O_CREAT,O_NOFOLLOW=0)
            with patch('approval_portal.os',fake):
                CallbackLog('/private/owner-portal.jsonl')({'stage':'callback_received'})
                fake.write.assert_not_called()

    async def test_full_gateway_callback_mux_accepts_issuer_and_split_owned_cookie(self):
        from approval_portal import NotifyingApprovalPortal
        from gateway import create_app
        from test_gateway import config as gateway_config,FakeChannel,catalog
        instances=[];records=[];exchange=AsyncMock(return_value=42)
        def portal_factory(cfg,**kwargs):
            kwargs.pop("list_sessions",None);kwargs.pop("revoke_sessions",None)
            value=NotifyingApprovalPortal(cfg,**kwargs,exchange_identity=exchange,diagnostics=records.append)
            instances.append(value);return value
        channel=FakeChannel()
        with patch('gateway.SessionApprovalPortal',side_effect=portal_factory):
            app=create_app(gateway_config(),channel,catalog())
        async def http_upstream(scope,receive,send):
            await app({**scope,'scheme':'http'},receive,send)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=http_upstream),
                    base_url=PUBLIC,follow_redirects=False) as client:
                start=await client.get(BASE+'login',params={'pending':PENDING})
                self.assertEqual(303,start.status_code)
                state=parse_qs(urlparse(start.headers['location']).query)['state'][0]
                cookie=client.cookies.get(LOGIN_COOKIE)
                callback=await client.get(CALLBACK,params={'state':state,'code':'synthetic-code',
                    'iss':GITHUB_ISSUER,'future_extension':'ignored'},headers=[
                        ('Cookie','unrelated=one; unrelated=two'),('Cookie',LOGIN_COOKIE+'='+cookie)])
                self.assertEqual(303,callback.status_code)
                self.assertEqual(PUBLIC+BASE+PENDING,callback.headers['location'])
                self.assertTrue(client.cookies.get(OWNER_COOKIE))
        exchange.assert_awaited_once()
        self.assertFalse(channel.calls)
        self.assertEqual(1,len(instances))
        self.assertIn('callback_session_created',[r['stage'] for r in records])


if __name__=='__main__':
    unittest.main()

import tempfile
from pathlib import Path
import json
from approval_portal import (NotifyingApprovalPortal, PushFiles, PushDelivery, push_subscription,
    push_encrypt, push_b64, push_unb64, push_public, ec, serialization, _digest, PUSH_SW, PUSH_JS)


def fixture_subscription(endpoint='https://web.push.apple.com/fixture-subscription'):
    key=ec.generate_private_key(ec.SECP256R1())
    public=key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    return {'endpoint':endpoint,'keys':{'p256dh':push_b64(public),'auth':push_b64(b'a'*16)}}


class PushCryptoTests(unittest.TestCase):
    def test_rfc8291_published_vector(self):
        sub={'endpoint':'https://web.push.apple.com/test','keys':{
            'p256dh':'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
            'auth':'BTBZMqHH6r4Tts7J_aSIgg'}}
        sender=ec.derive_private_key(int.from_bytes(push_unb64('yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',32),'big'),ec.SECP256R1())
        body=push_encrypt(sub,b'When I grow up, I want to be a watermelon',salt=push_unb64('DGv6ra1nlYgDCS1FRnbzlw',16),sender=sender)
        self.assertEqual('8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ',push_b64(body[86:]))
        self.assertEqual(4096,int.from_bytes(body[16:20],'big'))

    def test_rejects_arbitrary_and_local_destinations(self):
        for endpoint in ['http://web.push.apple.com/x','https://127.0.0.1/x','https://reach.example.invalid/x',
            'https://web.push.apple.com.evil.test/x','https://web.push.apple.com:444/x',('https://' + '@'.join(('user', 'web.push.apple.com')) + '/x'),
            'https://web.push.apple.com/x#fragment','https://web.push.apple.com/','https://web.push.apple.com/x\r\nHeader:value']:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):push_subscription(fixture_subscription(endpoint))

    def test_rejects_bad_keys_and_oversize_payload(self):
        sub=fixture_subscription();sub['keys']['auth']=push_b64(b'a'*15)
        with self.assertRaises(ValueError):push_subscription(sub)
        sub=fixture_subscription();sub['keys']['p256dh']=push_b64(b'a'*65)
        with self.assertRaises(ValueError):push_subscription(sub)
        with self.assertRaises(ValueError):push_encrypt(fixture_subscription(),b'x'*3001)

    def test_private_settings_survive_restart_and_bind_owner(self):
        with tempfile.TemporaryDirectory() as root:
            first=PushFiles(root).settings('42');second=PushFiles(root).settings('42')
            self.assertEqual(first,second);self.assertEqual(65,len(push_unb64(push_public(first),65)))
            with self.assertRaises(ValueError):PushFiles(root).settings('43')


class PushBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory=tempfile.TemporaryDirectory();self.now=1000.0;self.entries={}
        self.read=AsyncMock(return_value={'state':'awaiting_owner','vm_id':'vm-beta','script':'SECRET SCRIPT',
            'arguments':[],'timeout_seconds':60,'request_sha256':'a'*64,'expires_at':1600})
        self.decide=AsyncMock()
        self.portal=NotifyingApprovalPortal(config(),get_pending=self.read,decide_pending=self.decide,
            exchange_identity=AsyncMock(return_value=42),clock=lambda:self.now,push_root=self.directory.name,pending_feed=lambda:self.entries)
        app=Starlette(routes=self.portal.routes()+[Route(CALLBACK,self.portal.handle_callback)])
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url=PUBLIC,follow_redirects=False)

    async def asyncTearDown(self):
        await self.client.aclose();self.directory.cleanup()

    async def login(self):
        response=await self.client.get(BASE+'login?pending=home')
        state=parse_qs(urlparse(response.headers['location']).query)['state'][0]
        response=await self.client.get(CALLBACK,params={'state':state,'code':'fixture','iss':GITHUB_ISSUER})
        self.assertEqual(PUBLIC+BASE,response.headers['location'])
        self.csrf=(await self.client.get(BASE+'push/config')).json()['csrf']

    async def post(self,action,data,**kwargs):
        headers={'Origin':PUBLIC,'X-Reach-CSRF':self.csrf};headers.update(kwargs.pop('headers',{}))
        return await self.client.post(BASE+'push/'+action,json=data,headers=headers,**kwargs)

    async def test_home_and_manifest_public_but_subscriptions_private(self):
        home=await self.client.get(BASE);self.assertEqual(200,home.status_code);self.assertIn('Sign in with GitHub',home.text)
        manifest=(await self.client.get(BASE+'manifest.webmanifest')).json()
        self.assertEqual(BASE,manifest['start_url']);self.assertEqual('standalone',manifest['display'])
        self.assertEqual(403,(await self.client.get(BASE+'push/config')).status_code)
        self.assertTrue((await self.client.get(BASE+'icon.png')).content.startswith(b'\x89PNG'))
        self.decide.assert_not_awaited()

    async def test_login_register_test_unregister(self):
        await self.login();sub=fixture_subscription()
        self.assertEqual(200,(await self.post('subscribe',{'subscription':sub})).status_code)
        self.assertEqual(200,(await self.post('test',{'endpoint':sub['endpoint']})).status_code)
        self.assertEqual(400,(await self.post('test',{'endpoint':sub['endpoint']})).status_code)
        self.assertEqual(1,len(self.portal.push_files.read('events.json')['events']))
        self.assertEqual(200,(await self.post('unsubscribe',{'endpoint':sub['endpoint']})).status_code)
        self.assertFalse(self.portal.push_files.settings('42')['devices']);self.decide.assert_not_awaited()

    async def test_csrf_origin_expiry_and_owner_required(self):
        await self.login();data={'subscription':fixture_subscription()}
        for headers in ({'Origin':'https://evil.test'},{'X-Reach-CSRF':'wrong'},{'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(403,(await self.post('subscribe',data,headers=headers)).status_code)
        self.now=1601
        self.assertEqual(403,(await self.post('subscribe',data)).status_code)
        self.assertFalse(self.portal.push_files.settings('42')['devices'])

    async def test_cross_session_csrf_refused(self):
        await self.login();old=self.csrf;self.client.cookies.clear();await self.login()
        self.assertEqual(403,(await self.post('subscribe',{'subscription':fixture_subscription()},headers={'X-Reach-CSRF':old})).status_code)

    async def test_no_command_or_secret_in_feed_and_closed_removed(self):
        self.entries[PENDING]={'state':'awaiting_owner_approval','binding':{'subject':'42'}}
        await self.portal.publish_feed();raw=Path(self.directory.name,'events.json').read_text()
        self.assertIn(PENDING,raw);self.assertNotIn('SECRET SCRIPT',raw);self.assertNotIn('csrf',raw)
        self.entries[PENDING]['closed']='released';await self.portal.publish_feed()
        self.assertFalse(self.portal.push_files.read('events.json')['events']);self.decide.assert_not_awaited()

    async def test_wrong_owner_and_nonwaiting_not_advertised(self):
        self.entries[PENDING]={'state':'awaiting_owner_approval','binding':{'subject':'43'}}
        self.assertEqual([],await self.portal.snapshot())
        self.entries[PENDING]={'state':'running','binding':{'subject':'42'}}
        self.assertEqual([],await self.portal.snapshot());self.read.assert_not_awaited()

    async def test_subscription_limit_and_input_bounds(self):
        await self.login()
        for number in range(8):self.assertEqual(200,(await self.post('subscribe',{'subscription':fixture_subscription('https://web.push.apple.com/'+str(number))})).status_code)
        self.assertEqual(400,(await self.post('subscribe',{'subscription':fixture_subscription()})).status_code)
        self.assertEqual(413,(await self.post('subscribe',{'subscription':'x'*9000})).status_code)

    async def test_existing_approval_login_destination_preserved(self):
        response=await self.client.get(BASE+'login?pending='+PENDING)
        state=parse_qs(urlparse(response.headers['location']).query)['state'][0]
        response=await self.client.get(CALLBACK,params={'state':state,'code':'fixture'})
        self.assertEqual(PUBLIC+BASE+PENDING,response.headers['location'])


class PushDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory=tempfile.TemporaryDirectory();self.now=1000
        self.files=PushFiles(self.directory.name);settings=self.files.settings('42');self.sub=fixture_subscription()
        self.device=_digest(self.sub['endpoint']);settings['devices'][self.device]=self.sub;self.files.write('settings.json',settings)
        self.event={'id':PENDING,'vm_id':'vm-beta','created_at':1000,'expires_at':1600,'kind':'approval','device':''}
        self.send=AsyncMock(return_value=201);self.worker=PushDelivery(self.directory.name,clock=lambda:self.now,send=self.send)
        self.feed()

    async def asyncTearDown(self):self.directory.cleanup()
    def feed(self,events=None):self.files.write('events.json',{'updated_at':self.now,'events':[self.event] if events is None else events})

    async def test_send_once_remind_once_and_persist_across_worker_restart(self):
        await self.worker.tick();await self.worker.tick();self.assertEqual(1,self.send.await_count)
        worker=PushDelivery(self.directory.name,clock=lambda:self.now,send=self.send);await worker.tick();self.assertEqual(1,self.send.await_count)
        self.now=1121;self.feed();await worker.tick();self.assertEqual(2,self.send.await_count)
        self.now=1400;self.feed();await worker.tick();self.assertEqual(2,self.send.await_count)

    async def test_revoked_or_stale_feed_stops_delivery(self):
        self.feed([]);await self.worker.tick();self.send.assert_not_awaited()
        self.feed();self.now=1040;await self.worker.tick();self.send.assert_not_awaited()

    async def test_expired_and_unsubscribed_do_not_send(self):
        self.now=1601;self.feed();await self.worker.tick();self.send.assert_not_awaited()
        self.now=1000;self.feed();settings=self.files.settings('42');settings['devices']={};self.files.write('settings.json',settings)
        await self.worker.tick();self.send.assert_not_awaited()

    async def test_dead_subscription_not_retried(self):
        self.send.return_value=410;await self.worker.tick();self.now+=31;self.feed();await self.worker.tick()
        self.assertEqual(1,self.send.await_count);self.assertIn(self.device,self.files.read('delivery.json')['invalid'])

    async def test_transient_delivery_failure_retries_are_bounded(self):
        self.send.return_value=503
        for number in range(8):self.now=1000+31*number;self.feed();await self.worker.tick()
        self.assertEqual(4,self.send.await_count)

    async def test_test_notification_is_device_specific_and_single(self):
        self.event.update(kind='test',device=self.device);self.feed();await self.worker.tick()
        self.now=1121;self.feed();await self.worker.tick();self.assertEqual(1,self.send.await_count)
        self.assertEqual(PUBLIC+BASE,self.send.await_args.args[2]['url'])

    async def test_notifications_include_link_but_no_operation_payload(self):
        await self.worker.tick();message=self.send.await_args.args[2]
        self.assertEqual(PUBLIC+BASE+PENDING,message['url']);self.assertNotIn('script',message);self.assertNotIn('workflow_token',message)

    async def test_actual_sender_uses_valid_vapid_encrypted_payload_and_no_redirects(self):
        from approval_portal import jwt
        requests=[]
        def receive(request):requests.append(request);return httpx.Response(201)
        original=httpx.AsyncClient
        def client(**kwargs):
            self.assertFalse(kwargs['follow_redirects']);self.assertFalse(kwargs['trust_env'])
            return original(transport=httpx.MockTransport(receive),**kwargs)
        settings=self.files.settings('42')
        with patch('approval_portal.httpx.AsyncClient',side_effect=client):
            status=await self.worker.send(settings,self.sub,{'title':'Private test'},120,'test')
        self.assertEqual(201,status);request=requests[0]
        self.assertEqual('aes128gcm',request.headers['Content-Encoding']);self.assertEqual('120',request.headers['TTL'])
        self.assertNotIn(b'Private test',request.content)
        token=request.headers['Authorization'].split('t=',1)[1].split(',')[0]
        key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),push_unb64(push_public(settings),65))
        claims=jwt.decode(token,key,algorithms=['ES256'],audience='https://web.push.apple.com',options={'verify_exp':False})
        self.assertEqual(PUBLIC+BASE,claims['sub']);self.assertEqual(4600,claims['exp'])

    async def test_cancellation_during_first_device_delivery_stops_second(self):
        settings=self.files.settings('42');other=fixture_subscription('https://web.push.apple.com/other')
        settings['devices'][_digest(other['endpoint'])]=other;self.files.write('settings.json',settings)
        async def stop(*args):self.feed([]);return 201
        self.send.side_effect=stop
        await self.worker.tick();self.assertEqual(1,self.send.await_count)
