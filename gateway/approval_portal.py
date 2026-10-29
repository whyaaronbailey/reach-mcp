"""Owner-only browser approval. Browser identity is never administrator consent.

The injected frontend owns operation binding and broker dispatch. This module owns
independent browser authentication, exact review, CSRF and a one-use POST fence.
All memory is process-local: restart invalidates browser sessions and forms.
"""
import asyncio
import base64
import hashlib
import html
import json
import math
import os
import re
import secrets
import stat
import time
from urllib.parse import parse_qsl, urlencode

import httpx
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

PUBLIC = 'https://reach.example.invalid'
GITHUB_ISSUER = 'https://github.com/login/oauth'
CALLBACK = '/auth/callback/reach/nexus/auth/callback'
BASE = '/reach/nexus/admin/'
STATE_PREFIX = 'reach-owner-v1.'
OWNER_COOKIE = '__Host-ReachOwner'
LOGIN_COOKIE = '__Host-ReachOwnerLogin'
ID = re.compile(r'^[0-9a-f]{32}$')
TOKEN = re.compile(r'^[A-Za-z0-9_-]{43}$')
STYLE = ('body{font:17px system-ui,sans-serif;line-height:1.5;max-width:52rem;margin:auto;padding:1rem;color:#171717;background:#fff}'
    'h1{font-size:1.5rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:1rem;border-radius:.4rem}'
    'dd{margin:0 0 .8rem;overflow-wrap:anywhere}button{font:inherit;min-height:48px;min-width:132px;padding:.7rem 1.1rem;margin:.5rem .5rem .5rem 0}'
    'details{margin:1rem 0}summary{cursor:pointer;min-height:44px}form{margin:1.5rem 0}')
STYLE_HASH = base64.b64encode(hashlib.sha256(STYLE.encode('utf-8')).digest()).decode('ascii')
HEADERS = {'Cache-Control':'no-store, private', 'Pragma':'no-cache',
    'Content-Security-Policy':"default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'sha256-"+STYLE_HASH+"'",
    'Referrer-Policy':'same-origin', 'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY'}


def _digest(value):
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def _escape(value):
    return html.escape(str(value), quote=True)


def is_portal_state(state):
    """Reserved prefix detection only; malformed reserved states still fail closed."""
    return isinstance(state, str) and state.startswith(STATE_PREFIX)


class PortalUnavailable(Exception):
    pass


def owned_cookies(headers):
    """RFC 9113 cookie crumbs; only our two names participate in authentication."""
    shape={'cookie_header_count':min(len(headers),16384),'owned_cookie_count':0,
           'duplicate_owned_cookie':False,'cookie_parse_ok':False}
    if any(type(h) is not str for h in headers) or sum(len(h) for h in headers)>16384:
        return None,shape
    found={}
    for header in headers:
        if any(c in header for c in ('\r','\n','\0')):
            return None,shape
        for part in header.split(';'):
            name,separator,value=part.strip().partition('=')
            if name not in (OWNER_COOKIE,LOGIN_COOKIE):
                continue
            shape['owned_cookie_count']+=1
            if name in found:
                shape['duplicate_owned_cookie']=True
                return None,shape
            if separator!='=' or not TOKEN.fullmatch(value):
                return None,shape
            found[name]=value
    shape['cookie_parse_ok']=True
    return found,shape


class CallbackLog:
    """Bounded private metadata only. Logging never supplies approval authority."""
    STAGES=frozenset({'callback_received','callback_query_received','callback_refused_transport','callback_refused_query',
        'callback_refused_issuer','callback_refused_shape','callback_refused_state',
        'callback_refused_cookie_binding','callback_state_consumed','callback_exchange_failed',
        'callback_owner_checked','callback_refused_owner','callback_refused_capacity',
        'callback_session_created','provider_response','provider_body_refused'})
    FIELDS=frozenset({'cookie_header_count','owned_cookie_count','duplicate_owned_cookie','cookie_parse_ok',
        'scheme_ok','host_ok','path_ok','query_count','query_duplicates','issuer_present','issuer_ok',
        'state_present','code_present','state_known','owner_matches','owner_id_is_integer',
        'timeout','connect_or_tls','http_status','token_endpoint','administrator_permission_granted'})

    def __init__(self,path='/state/reach-admin/owner-portal.jsonl',limit=262144):
        self.path,self.limit=path,limit

    @classmethod
    def safe(cls,record):
        return (type(record) is dict and type(record.get('stage')) is str and record['stage'] in cls.STAGES
            and set(record)-{'stage'}<=cls.FIELDS
            and all(type(v) is bool or (type(v) is int and 0<=v<=16384)
                    for k,v in record.items() if k!='stage'))

    def __call__(self,record):
        if os.name!='posix' or not self.safe(record):
            return
        fd=None
        try:
            parent=os.path.dirname(self.path);os.makedirs(parent,mode=0o700,exist_ok=True)
            info=os.stat(parent,follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
                return
            if os.path.lexists(self.path):
                info=os.stat(self.path,follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                        or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
                    return
                if info.st_size>self.limit:
                    os.replace(self.path,self.path+'.1')
            fd=os.open(self.path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                    or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
                return
            raw=(json.dumps({'utc':time.time(),**record},separators=(',',':'))+'\n').encode('ascii')
            if len(raw)<=4096:os.write(fd,raw)
        except (OSError,TypeError,ValueError):
            pass
        finally:
            if fd is not None:os.close(fd)


class OwnerApprovalPortal:
    def __init__(self, config, *, get_pending, decide_pending, exchange_identity=None,
                 clock=time.time, session_ttl_seconds=86400, transport_scheme='https',diagnostics=None):
        oauth = config.get('oauth_config', {}) if type(config) is dict else {}
        ids = oauth.get('allowed_github_user_ids')
        if (oauth.get('public_url') != PUBLIC or type(ids) is not list or len(ids) != 1
                or type(ids[0]) is not int or ids[0] <= 0):
            raise ValueError('Exact Nexus origin and immutable owner ID required.')
        if any(not isinstance(oauth.get(k), str) or len(oauth[k]) < 20
                for k in ('client_id', 'client_secret')):
            raise ValueError('Existing MCP GitHub application configuration required.')
        portal_oauth = oauth.get('owner_approval_oauth')
        if (type(portal_oauth) is not dict or set(portal_oauth) != {'client_id', 'client_secret'}
                or any(not isinstance(portal_oauth[k], str) or len(portal_oauth[k]) < 20
                       or portal_oauth[k].startswith('PASTE') for k in ('client_id', 'client_secret'))
                or portal_oauth['client_id'] == oauth['client_id']):
            raise ValueError('A separate owner approval GitHub application is required.')
        if type(session_ttl_seconds) is not int or not 300 <= session_ttl_seconds <= 86400:
            raise ValueError('Invalid browser identity lifetime.')
        if transport_scheme not in ('https', 'http'):
            raise ValueError('A fixed reviewed upstream transport scheme is required.')
        self.owner = str(ids[0])
        self.client_id, self.client_secret = portal_oauth['client_id'], portal_oauth['client_secret']
        self.get_pending, self.decide_pending = get_pending, decide_pending
        self.exchange_identity = exchange_identity or self._github_identity
        self.clock, self.session_ttl = clock, session_ttl_seconds
        self.transport_scheme = transport_scheme
        self.diagnostics=diagnostics if diagnostics is not None else CallbackLog()
        self.logins, self.sessions, self.forms, self.consumed = {}, {}, {}, {}
        self.lock = asyncio.Lock()

    @staticmethod
    def is_portal_state(state):
        return is_portal_state(state)

    def review_url(self, pending_id):
        if not isinstance(pending_id, str) or not ID.fullmatch(pending_id):
            raise ValueError('Invalid pending ID.')
        return PUBLIC + BASE + pending_id

    def routes(self):
        return [Route(BASE+'login', self.login, methods=['GET']),
                Route(BASE+'{pending_id}', self.review, methods=['GET', 'POST'])]

    def _prune(self):
        now = self.clock()
        for store in (self.logins, self.sessions, self.forms, self.consumed):
            for key in tuple(store):
                if store[key]['expires_at'] <= now:
                    del store[key]

    def _record(self,stage,**fields):
        record={'stage':stage,'administrator_permission_granted':False,**fields}
        if CallbackLog.safe(record):
            try:self.diagnostics(record)
            except Exception:pass

    def _host_ok(self, request, path):
        cookies,_=owned_cookies(request.headers.getlist('cookie'))
        # TLS is an ingress policy when the reviewed local Uvicorn upstream is HTTP.
        # This fixed constructor setting never trusts forwarded scheme headers.
        return (cookies is not None and request.url.scheme == self.transport_scheme
            and request.headers.getlist('host') == ['reach.example.invalid']
            and request.scope.get('root_path', '') == ''
            and request.scope.get('path') == path
            and request.scope.get('raw_path', path.encode('ascii')) == path.encode('ascii'))

    def _page(self, title, body, status=200):
        return HTMLResponse('<!doctype html><html><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>'+_escape(title)+'</title><style>'+STYLE+'</style></head><body><h1>'+_escape(title)+'</h1>'
            +body+'</body></html>', status_code=status, headers=HEADERS)

    def _denied(self, status=403):
        return self._page('Approval unavailable',
            '<p>No administrator permission was granted. Return to Reach and check the request status.</p>', status)

    def _redirect(self, url):
        return RedirectResponse(url, status_code=303, headers=HEADERS)

    def _cookie(self, response, name, value, age):
        response.set_cookie(name, value, max_age=age, secure=True, httponly=True,
                            samesite='lax', path='/')

    def _browser(self, request):
        cookies,_=owned_cookies(request.headers.getlist('cookie'))
        value = cookies.get(OWNER_COOKIE, '') if cookies is not None else ''
        if not TOKEN.fullmatch(value):
            return None
        key = _digest(value)
        session = self.sessions.get(key)
        if not session or session['expires_at'] <= self.clock() or session['owner'] != self.owner:
            return None
        return key

    async def login(self, request):
        if not self._host_ok(request, BASE+'login'):
            return self._denied()
        query = list(request.query_params.multi_items())
        if len(query) != 1 or query[0][0] != 'pending' or not ID.fullmatch(query[0][1]):
            return self._denied(400)
        pending_id = query[0][1]
        async with self.lock:
            self._prune()
            if self._browser(request):
                return self._redirect(self.review_url(pending_id))
            if len(self.logins) >= 256:
                return self._denied(503)
            nonce, cookie, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            state = STATE_PREFIX + nonce
            self.logins[state] = {'cookie':_digest(cookie), 'verifier':verifier,
                'pending_id':pending_id, 'expires_at':self.clock()+300}
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
        response = self._redirect('https://github.com/login/oauth/authorize?'+urlencode({
            'client_id':self.client_id, 'redirect_uri':PUBLIC+CALLBACK, 'scope':'read:user',
            'state':state, 'code_challenge':challenge, 'code_challenge_method':'S256'}))
        self._cookie(response, LOGIN_COOKIE, cookie, 300)
        return response

    async def handle_callback(self, request):
        cookies,shape=owned_cookies(request.headers.getlist('cookie'))
        self._record('callback_received',**shape,scheme_ok=request.url.scheme==self.transport_scheme,
            host_ok=request.headers.getlist('host')==['reach.example.invalid'],
            path_ok=request.scope.get('path')==CALLBACK and request.scope.get('raw_path',CALLBACK.encode())==CALLBACK.encode())
        if not self._host_ok(request, CALLBACK):
            self._record('callback_refused_transport')
            return self._denied()
        pairs = list(request.query_params.multi_items())
        query = dict(pairs)
        self._record('callback_query_received',query_count=min(len(pairs),16384),query_duplicates=len(query)!=len(pairs),
            issuer_present='iss' in query,issuer_ok='iss' not in query or query['iss']==GITHUB_ISSUER,
            state_present='state' in query,code_present='code' in query)
        # RFC 6749 response extensions are ignored; recognized fields still have
        # strict semantics. RFC 9207 issuer identification is checked if present.
        if len(query) != len(pairs) or len(request.scope.get('query_string',b''))>16384:
            self._record('callback_refused_query')
            return self._denied(400)
        if 'iss' in query and query['iss']!=GITHUB_ISSUER:
            self._record('callback_refused_issuer')
            return self._denied()
        state, code = query.get('state', ''), query.get('code', '')
        cookie = cookies.get(LOGIN_COOKIE, '')
        if (not is_portal_state(state) or not TOKEN.fullmatch(state[len(STATE_PREFIX):])
                or not TOKEN.fullmatch(cookie) or not isinstance(code, str)
                or not 1 <= len(code) <= 2048 or any(ord(c) < 32 for c in code) or 'error' in query):
            self._record('callback_refused_shape')
            return self._denied()
        async with self.lock:
            self._prune()
            login = self.logins.get(state)
            if not login:
                self._record('callback_refused_state',state_known=False)
                return self._denied()
            if not secrets.compare_digest(login['cookie'], _digest(cookie)):
                self._record('callback_refused_cookie_binding',state_known=True)
                return self._denied()
            # Consume state before exchange. A duplicate callback never exchanges again.
            del self.logins[state]
        self._record('callback_state_consumed')
        try:
            owner_id = await self.exchange_identity(code, login['verifier'])
        except Exception as error:
            self._record('callback_exchange_failed',timeout=isinstance(error,httpx.TimeoutException),
                         connect_or_tls=isinstance(error,httpx.ConnectError))
            return self._denied()
        self._record('callback_owner_checked',owner_id_is_integer=type(owner_id) is int,
            owner_matches=type(owner_id) is int and str(owner_id)==self.owner)
        if type(owner_id) is not int or str(owner_id) != self.owner:
            self._record('callback_refused_owner')
            return self._denied()
        token = secrets.token_urlsafe(32)
        async with self.lock:
            self._prune()
            if len(self.sessions) >= 256:
                self._record('callback_refused_capacity')
                return self._denied(503)
            self.sessions[_digest(token)] = {'owner':self.owner, 'expires_at':self.clock()+self.session_ttl}
        self._record('callback_session_created')
        response = self._redirect(self.review_url(login['pending_id']))
        self._cookie(response, OWNER_COOKIE, token, self.session_ttl)
        response.delete_cookie(LOGIN_COOKIE, path='/', secure=True, httponly=True, samesite='lax')
        return response

    async def _github_identity(self, code, verifier):
        # No configurable provider URLs, MCP bearer, forwarded credentials or redirects.
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            async def bounded_json(method, url, **kwargs):
                async with client.stream(method, url, **kwargs) as response:
                    self._record('provider_response',token_endpoint=method=='POST',http_status=response.status_code)
                    if response.status_code != 200:
                        raise PortalUnavailable()
                    body = bytearray()
                    async for part in response.aiter_bytes():
                        body.extend(part)
                        if len(body) > 65536:
                            self._record('provider_body_refused',token_endpoint=method=='POST')
                            raise PortalUnavailable()
                    value = json.loads(body)
                    if type(value) is not dict:
                        raise PortalUnavailable()
                    return value
            token = await bounded_json('POST', 'https://github.com/login/oauth/access_token',
                headers={'Accept':'application/json', 'User-Agent':'Reach-Nexus-owner-approval'},
                data={'client_id':self.client_id, 'client_secret':self.client_secret,
                      'code':code, 'redirect_uri':PUBLIC+CALLBACK, 'code_verifier':verifier})
            bearer = token.get('access_token')
            if (not isinstance(bearer, str) or not 1 <= len(bearer) <= 8192
                    or token.get('token_type', '').lower() != 'bearer' or 'error' in token
                    or any(ord(c) < 33 or ord(c) > 126 for c in bearer)):
                raise PortalUnavailable()
            user = await bounded_json('GET', 'https://api.github.com/user', headers={
                'Authorization':'Bearer '+bearer, 'Accept':'application/vnd.github+json',
                'User-Agent':'Reach-Nexus-owner-approval', 'X-GitHub-Api-Version':'2022-11-28'})
            return user.get('id')

    def _validate_view(self, view):
        if type(view) is not dict or not isinstance(view.get('state'), str):
            raise PortalUnavailable()
        if view['state'] != 'awaiting_owner':
            return False
        if (not isinstance(view.get('vm_id'), str) or not re.fullmatch(r'[a-z0-9-]{1,64}', view['vm_id'])
                or not isinstance(view.get('script'), str) or not view['script'] or '\0' in view['script']
                or len(view['script'].encode('utf-8')) > 16384
                or type(view.get('arguments')) is not list or len(view['arguments']) > 32
                or any(not isinstance(x, str) or '\0' in x or len(x.encode('utf-8')) > 8192 for x in view['arguments'])
                or sum(len(x.encode('utf-8')) for x in view['arguments']) > 32768
                or type(view.get('timeout_seconds')) is not int or not 1 <= view['timeout_seconds'] <= 300
                or not isinstance(view.get('request_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', view['request_sha256'])
                or type(view.get('expires_at')) not in (int, float)
                or not math.isfinite(view['expires_at']) or view['expires_at'] <= self.clock()):
            raise PortalUnavailable()
        return True

    async def review(self, request):
        pending_id = request.path_params.get('pending_id', '')
        if (not isinstance(pending_id, str) or not ID.fullmatch(pending_id)
                or not self._host_ok(request, BASE+pending_id) or request.query_params):
            return self._denied(404)
        async with self.lock:
            self._prune()
            browser = self._browser(request)
        if browser is None:
            if request.method == 'POST':
                return self._denied()
            return self._redirect(PUBLIC+BASE+'login?'+urlencode({'pending':pending_id}))
        if request.method == 'POST':
            return await self._submit(request, pending_id, browser)
        try:
            view = await self.get_pending(pending_id, self.owner)
            waiting = self._validate_view(view)
        except Exception:
            return self._denied(404)
        if not waiting:
            return self._page('Reach request status', '<p>This request is no longer awaiting approval. '
                'Return to Reach to read its status. No new operation was started by this page.</p>')
        csrf = secrets.token_urlsafe(32)
        async with self.lock:
            self._prune()
            if (self._browser(request) != browser or pending_id in self.consumed
                    or len(self.forms) >= 1024):
                return self._denied(409)
            self.forms[_digest(csrf)] = {'browser':browser, 'pending_id':pending_id,
                'request_sha256':view['request_sha256'], 'session_allowed':view.get('session_allowed') is True,
                'expires_at':min(view['expires_at'], self.sessions[browser]['expires_at'], self.clock()+300)}
        session_button = ('<button type="submit" name="choice" value="workflow">Allow for this Reach session</button> ' if view.get('session_allowed') is True else '')
        scope_note = ('<p>Session permission allows unlimited administrator operations on this VM until the agent releases its Reach reservation, the reservation expires, Reach restarts, or you revoke it. It does not carry into a new reservation. Already admitted commands may finish.</p>' if session_button else '')
        script_hash = hashlib.sha256(view['script'].encode('utf-8')).hexdigest()
        body = ('<p>Review the administrator operation below. Signing in or opening this page grants nothing.</p>'+scope_note+
            '<dl><dt>VM</dt><dd>'+_escape(view['vm_id'])+'</dd><dt>Timeout (seconds)</dt><dd>'
            +str(view['timeout_seconds'])+'</dd></dl><h2>PowerShell script</h2><pre>'
            +_escape(view['script'])+'</pre><h2>Arguments (JSON)</h2><pre>'
            +_escape(json.dumps(view['arguments'], ensure_ascii=True))+'</pre><details>'
            '<summary>Verification hashes and escaped script</summary><dl><dt>Request SHA-256</dt><dd>'
            +_escape(view['request_sha256'])+'</dd><dt>Script SHA-256 (UTF-8)</dt><dd>'+script_hash
            +'</dd></dl><pre>'+_escape(json.dumps(view['script'], ensure_ascii=True))+'</pre></details>'
            '<form method="post" action="'
            +BASE+pending_id+'"><input type="hidden" name="csrf" value="'+csrf+'">'
            '<button type="submit" name="choice" value="once">Approve once</button> '
            +session_button+'<button type="submit" name="choice" value="deny">Deny</button></form>')
        return self._page('Review Reach administrator operation', body)

    async def _submit(self, request, pending_id, browser):
        origins, types = request.headers.getlist('origin'), request.headers.getlist('content-type')
        if (origins != [PUBLIC]
                or request.headers.getlist('sec-fetch-site') not in ([], ['same-origin'])
                or len(types) != 1 or types[0].split(';', 1)[0].strip().lower()
                   != 'application/x-www-form-urlencoded'):
            return self._denied()
        body = bytearray()
        async for part in request.stream():
            body.extend(part)
            if len(body) > 4096:
                return self._denied(413)
        try:
            pairs = parse_qsl(body.decode('ascii'), keep_blank_values=True, strict_parsing=True)
            form = dict(pairs)
            if (len(pairs) != 2 or set(form) != {'csrf', 'choice'} or not TOKEN.fullmatch(form['csrf'])
                    or form['choice'] not in ('once', 'workflow', 'deny')):
                return self._denied(400)
        except (ValueError, UnicodeError):
            return self._denied(400)
        try:
            view = await self.get_pending(pending_id, self.owner)
            if not self._validate_view(view):
                return self._denied(409)
        except Exception:
            return self._denied(409)
        async with self.lock:
            self._prune()
            proof = self.forms.get(_digest(form['csrf']))
            if (self._browser(request) != browser or not proof or proof['browser'] != browser
                    or proof['pending_id'] != pending_id
                    or proof['request_sha256'] != view['request_sha256'] or pending_id in self.consumed
                    or (form['choice'] == 'workflow' and (proof.get('session_allowed') is not True or view.get('session_allowed') is not True))):
                return self._denied(409)
            # Consume before callback. Unknown dispatch outcomes can never be replayed.
            del self.forms[_digest(form['csrf'])]
            self.consumed[pending_id] = {'expires_at':max(view['expires_at'], self.clock()+300)}
        try:
            result = await self.decide_pending(pending_id, self.owner, form['choice'])
            if type(result) is not dict:
                raise PortalUnavailable()
        except Exception:
            return self._page('Reach decision status uncertain', '<p>The decision was consumed. '
                'Return to Reach and inspect its status before doing anything else. This page will not retry it.</p>', 503)
        state = result.get('state')
        if state == 'declined':
            return self._page('Reach operation denied', '<p>This operation was denied. It was not started. '
                'Return to Reach to continue. This page cannot change the denial or run the operation.</p>')
        if isinstance(state, str) and state in {'dispatching', 'outcome_uncertain'}:
            return self._page('Reach operation status uncertain', '<p>The approval was consumed and the operation '
                'may have started. Return to Reach and inspect its status. This page will not retry it.</p>', 202)
        if result.get('ok') is True and result.get('administrator_permission_granted') is True:
            if form['choice'] == 'workflow':
                return self._page('Reach session approved', '<p>Your session choice was recorded. Return to Reach to read the command result. You can revoke permission at any time from <a href="'+BASE+'">Reach Approvals</a>.</p>')
            return self._page('Reach operation approved once', '<p>Your approval was recorded for this one operation. '
                'Return to Reach to read its result. Approval does not mean execution succeeded; this page cannot run it again.</p>')
        return self._page('Reach request no longer available', '<p>No new administrator approval was granted by this page. '
            'Return to Reach to check whether the request expired, was released or was revoked.</p>', 409)

# Home Screen / Web Push extension. Notifications confer no execution authority.
from pathlib import Path
from urllib.parse import urlsplit
import hmac
import struct
import tempfile
import zlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt
from starlette.responses import JSONResponse, Response

PUSH_HOSTS = frozenset(('web.push.apple.com', 'fcm.googleapis.com', 'updates.push.services.mozilla.com'))


def push_b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def push_unb64(value, length):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', value):
        raise ValueError('Invalid push key.')
    result = base64.b64decode(value.rstrip('=')+'='*(-len(value.rstrip('=')) % 4), altchars=b'-_', validate=True)
    if len(result) != length:
        raise ValueError('Invalid push key length.')
    return result


def push_subscription(value):
    if type(value) is not dict or not set(value) <= {'endpoint', 'keys', 'expirationTime'}:
        raise ValueError('Invalid subscription.')
    endpoint, keys = value.get('endpoint'), value.get('keys')
    if not isinstance(endpoint, str) or not 1 <= len(endpoint) <= 2048 or any(ord(c) < 33 or ord(c) > 126 for c in endpoint):
        raise ValueError('Invalid push endpoint.')
    url = urlsplit(endpoint)
    if (url.scheme != 'https' or url.hostname not in PUSH_HOSTS or url.netloc != url.hostname
            or url.username or url.password or url.fragment or not url.path.startswith('/') or url.path == '/'):
        raise ValueError('This push provider is not supported.')
    if type(keys) is not dict or set(keys) != {'p256dh', 'auth'}:
        raise ValueError('Invalid subscription keys.')
    public = push_unb64(keys['p256dh'], 65)
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
    auth = push_unb64(keys['auth'], 16)
    return {'endpoint':endpoint, 'keys':{'p256dh':push_b64(public), 'auth':push_b64(auth)}}


def push_encrypt(subscription, message, *, salt=None, sender=None):
    """RFC 8291 aes128gcm, one bounded record; primitives supplied by cryptography."""
    sub = push_subscription(subscription)
    if not isinstance(message, bytes) or len(message) > 3000:
        raise ValueError('Push payload too large.')
    salt = os.urandom(16) if salt is None else salt
    if len(salt) != 16:
        raise ValueError('Invalid salt.')
    sender = sender or ec.generate_private_key(ec.SECP256R1())
    ua = push_unb64(sub['keys']['p256dh'], 65)
    public = sender.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = sender.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua))
    extract = lambda key, data: hmac.new(key, data, hashlib.sha256).digest()
    # Every expansion here is <= SHA-256's output length, so exactly one HKDF block.
    expand = lambda key, info, size: extract(key, info+b'\x01')[:size]
    ikm = expand(extract(push_unb64(sub['keys']['auth'], 16), shared), b'WebPush: info\x00'+ua+public, 32)
    prk = extract(salt, ikm)
    cek = expand(prk, b'Content-Encoding: aes128gcm\x00', 16)
    nonce = expand(prk, b'Content-Encoding: nonce\x00', 12)
    return salt+struct.pack('!IB', 4096, len(public))+public+AESGCM(cek).encrypt(nonce, message+b'\x02', None)


class PushFiles:
    """One private volume; gateway owns settings/feed, delivery worker owns ledger."""
    def __init__(self, root):
        self.root = Path(root)

    def directory(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or self.root.is_symlink():
            raise ValueError('Invalid push directory.')
        if os.name == 'posix' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('Push directory must be private.')

    def read(self, name, default=None):
        self.directory()
        path = self.root / name
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        except FileNotFoundError:
            return default
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 262144:
                raise ValueError('Invalid push file.')
            if os.name == 'posix' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('Push file must be private.')
            return json.loads(stream.read(262145))

    def write(self, name, value):
        self.directory()
        raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        if len(raw) > 262144:
            raise ValueError('Push state too large.')
        fd, temp = tempfile.mkstemp(prefix='.push-', dir=self.root)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, self.root/name)
            if os.name == 'posix':
                parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(parent)
                finally: os.close(parent)
        finally:
            if os.path.exists(temp): os.unlink(temp)

    def settings(self, owner=None):
        value = self.read('settings.json')
        if value is None and owner is not None:
            key = ec.generate_private_key(ec.SECP256R1())
            value = {'version':1, 'owner':owner, 'vapid':push_b64(key.private_numbers().private_value.to_bytes(32, 'big')), 'devices':{}}
            self.write('settings.json', value)
        if (type(value) is not dict or set(value) != {'version','owner','vapid','devices'} or value['version'] != 1
                or type(value['owner']) is not str or (owner is not None and value['owner'] != owner)
                or type(value['devices']) is not dict or len(value['devices']) > 8):
            raise ValueError('Invalid push settings.')
        ec.derive_private_key(int.from_bytes(push_unb64(value['vapid'], 32), 'big'), ec.SECP256R1())
        for identifier, sub in value['devices'].items():
            if push_subscription(sub) != sub or identifier != _digest(sub['endpoint']):
                raise ValueError('Invalid saved device.')
        return value


def push_public(settings):
    key = ec.derive_private_key(int.from_bytes(push_unb64(settings['vapid'], 32), 'big'), ec.SECP256R1())
    return push_b64(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


class PushDelivery:
    def __init__(self, root, *, clock=time.time, send=None):
        self.files, self.clock, self.send_override = PushFiles(root), clock, send

    async def send(self, settings, subscription, message, ttl, topic):
        key = ec.derive_private_key(int.from_bytes(push_unb64(settings['vapid'], 32), 'big'), ec.SECP256R1())
        endpoint = push_subscription(subscription)['endpoint']
        url = urlsplit(endpoint)
        token = jwt.encode({'aud':url.scheme+'://'+url.netloc, 'exp':int(self.clock())+3600, 'sub':PUBLIC+BASE}, key, algorithm='ES256')
        body = push_encrypt(subscription, json.dumps(message, separators=(',', ':')).encode())
        async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as client:
            async with client.stream('POST', endpoint, content=body, headers={
                'Authorization':'vapid t='+token+', k='+push_public(settings),
                'Content-Encoding':'aes128gcm', 'Content-Type':'application/octet-stream',
                'TTL':str(ttl), 'Urgency':'high', 'Topic':topic}) as response:
                return response.status_code

    async def tick(self):
        now = self.clock()
        settings = self.files.settings()
        feed = self.files.read('events.json', {'events':[], 'updated_at':0})
        ledger = self.files.read('delivery.json', {'sent':{}, 'invalid':{}, 'updated_at':0})
        if (type(feed) is not dict or set(feed) != {'events','updated_at'} or type(feed['events']) is not list
                or len(feed['events']) > 64 or type(feed['updated_at']) not in (int,float)
                or not 0 <= now-feed['updated_at'] <= 30):
            return
        if type(ledger) is not dict or set(ledger) != {'sent','invalid','updated_at'}:
            raise ValueError('Invalid delivery ledger.')
        ledger['sent'] = {k:v for k,v in ledger['sent'].items() if v.get('expires',0) > now}
        ledger['invalid'] = {k:v for k,v in ledger['invalid'].items() if k in settings['devices']}
        for event in feed['events']:
            if (type(event) is not dict or set(event) != {'id','vm_id','expires_at','created_at','kind','device'}
                    or not ID.fullmatch(str(event['id'])) or event['kind'] not in ('approval','test')
                    or not re.fullmatch(r'[a-z0-9-]{1,64}',str(event['vm_id']))
                    or type(event['expires_at']) not in (int,float) or type(event['created_at']) not in (int,float)
                    or not 0 < event['expires_at']-now <= 86400):
                continue
            for identifier, subscription in settings['devices'].items():
                if identifier in ledger['invalid'] or (event['device'] and event['device'] != identifier): continue
                # Recheck between sends: another device/provider may have been slow,
                # and the owner can unsubscribe or finish the operation meanwhile.
                now = self.clock()
                current_feed = self.files.read('events.json', {'events':[], 'updated_at':0})
                current_settings = self.files.settings()
                if (not 0 <= now-current_feed.get('updated_at',0) <= 30
                        or identifier not in current_settings['devices']
                        or current_settings['devices'][identifier] != subscription
                        or not any(e.get('id')==event['id'] and e.get('expires_at',0)>now for e in current_feed.get('events',[]))):
                    continue
                record_key = event['id']+':'+identifier
                record = ledger['sent'].get(record_key, {'count':0,'attempts':0,'next':0,'expires':event['expires_at']+600})
                limit = 1 if event['kind'] == 'test' else 2
                if record['count'] >= limit or record['attempts'] >= 4 or record['next'] > now: continue
                if record['count'] == 1 and now-event['created_at'] < 120: continue
                # Persist an attempt before sending; uncertain delivery cannot become an unbounded retry loop.
                record.update(attempts=record['attempts']+1, next=now+30, expires=event['expires_at']+600)
                ledger['sent'][record_key] = record
                self.files.write('delivery.json', ledger)
                test = event['kind'] == 'test'
                message = {'title':'Reach notifications are working' if test else 'Administrator approval needed',
                    'body':'Tap to return to Reach.' if test else event['vm_id']+' is waiting for your approval.',
                    'url':PUBLIC+BASE+('' if test else event['id']), 'tag':'reach-'+event['id'],
                    'expires_at':event['expires_at']}
                try:
                    sender = self.send_override or self.send
                    status = await sender(settings, subscription, message, max(1,min(300,int(event['expires_at']-now))), _digest(record_key)[:32])
                except Exception:
                    status = 0
                record['status'] = status
                if status in (200,201,202):
                    record.update(count=record['count']+1, next=now+120)
                elif status in (404,410):
                    ledger['invalid'][identifier] = int(now)
                elif status not in (0,408,429) and status < 500:
                    record['attempts'] = 4
                self.files.write('delivery.json', ledger)
        ledger['updated_at'] = int(self.clock())
        self.files.write('delivery.json', ledger)


async def run_push_delivery(root='/push'):
    worker = PushDelivery(root)
    while True:
        try: await worker.tick()
        except Exception: pass  # No subscription endpoint, key or token in logs.
        await asyncio.sleep(5)


PUSH_SW = r'''
self.addEventListener('push',event=>{
  let p={};try{p=event.data.json()}catch(e){}
  const base=self.location.origin+'/reach/nexus/admin/';
  const valid=typeof p.url==='string' && (p.url===base || new RegExp('^'+base.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'[a-f0-9]{32}$').test(p.url));
  const expired=typeof p.expires_at==='number' && Date.now()/1000>=p.expires_at;
  const title=expired?'Reach request expired':String(p.title||'Reach notification').slice(0,100);
  event.waitUntil(self.registration.showNotification(title,{body:expired?'Open Reach for current requests.':String(p.body||'Open Reach to review.').slice(0,200),tag:String(p.tag||'reach').slice(0,80),renotify:true,icon:base+'icon.png',badge:base+'icon.png',data:{url:valid&&!expired?p.url:base}}));
});
self.addEventListener('notificationclick',event=>{event.notification.close();const base=self.location.origin+'/reach/nexus/admin/';let u=event.notification.data?.url||base;if(!u.startsWith(base))u=base;event.waitUntil(clients.openWindow(u))});
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(clients.claim()));
'''

PUSH_JS = r'''
const base='/reach/nexus/admin/';let config,registration;
const status=document.getElementById('notification-status');
function show(text){status.textContent=text}
function bytes(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))}
async function request(action,data={}){const r=await fetch(base+'push/'+action,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Reach-CSRF':config.csrf},body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(j.error||'Request failed. Refresh this page and try again.');return j}
async function setup(){try{
 const r=await fetch(base+'push/config',{credentials:'same-origin'});if(!r.ok)throw Error('Sign in again to manage notifications.');config=await r.json();
 if(!('serviceWorker' in navigator)||!('PushManager' in window)||!('Notification' in window))throw Error('On iPhone, add this page to your Home Screen, then open Reach from that icon.');
 registration=await navigator.serviceWorker.register(base+'sw.js',{scope:base});await navigator.serviceWorker.ready;
 const sub=await registration.pushManager.getSubscription();show(sub?'This browser has a notification subscription. Use Send test notification to verify delivery.':'Notifications are off on this device.');
 document.querySelectorAll('[data-push]').forEach(b=>b.disabled=false);
 if(Notification.permission==='denied')show('Notifications are blocked. Enable them for Reach in iPhone Settings → Notifications.');
}catch(e){show(e.message)}}
document.getElementById('enable').onclick=async()=>{try{
 const permission=await Notification.requestPermission();if(permission!=='granted')throw Error('Notifications were not allowed. You can try again from Settings.');
 let sub=await registration.pushManager.getSubscription();if(!sub)sub=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:bytes(config.public_key)});
 await request('subscribe',{subscription:sub.toJSON()});show('Notifications enabled. Tap Send test notification, then leave this page to check the alert.');
}catch(e){show(e.message)}};
document.getElementById('test').onclick=async()=>{try{const sub=await registration.pushManager.getSubscription();if(!sub)throw Error('Enable notifications first.');await request('test',{endpoint:sub.endpoint});show('Test queued. Leave this page or lock your phone to check the notification.')}catch(e){show(e.message)}};
document.getElementById('disable').onclick=async()=>{try{const sub=await registration.pushManager.getSubscription();if(sub){await request('unsubscribe',{endpoint:sub.endpoint});await sub.unsubscribe()}show('Notifications disabled on this device.')}catch(e){show(e.message)}};
setup();
'''


def push_icon():
    size=192; rows=[]
    for y in range(size):
        row=bytearray([0])
        for x in range(size):
            letter=(48<=x<66 and 42<=y<150) or (60<=x<122 and (42<=y<60 or 86<=y<104)) or (112<=x<130 and 50<=y<96) or (92<=y<150 and 65+(y-92)*.7<=x<84+(y-92)*.7)
            row.extend((255,255,255) if letter else (25,78,180))
        rows.append(bytes(row))
    def chunk(kind, data): return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',size,size,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows)))+chunk(b'IEND',b'')


class NotifyingApprovalPortal(OwnerApprovalPortal):
    def __init__(self, *args, push_root='/state/reach-push', pending_feed=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.push_files=PushFiles(push_root);self.pending_feed=pending_feed or (lambda:{})
        self.push_forms={};self.push_tests={};self.push_created={}

    def review_url(self, pending_id):
        return PUBLIC+BASE if pending_id=='home' else super().review_url(pending_id)

    def routes(self):
        return [Route(BASE,self.home,methods=['GET']),Route(BASE+'manifest.webmanifest',self.asset,methods=['GET']),
            Route(BASE+'sw.js',self.asset,methods=['GET']),Route(BASE+'app.js',self.asset,methods=['GET']),
            Route(BASE+'icon.png',self.asset,methods=['GET']),Route(BASE+'push/config',self.push_config,methods=['GET']),
            Route(BASE+'push/{action}',self.push_action,methods=['POST']),*super().routes()]

    async def login(self, request):
        if list(request.query_params.multi_items()) != [('pending','home')]: return await super().login(request)
        if not self._host_ok(request,BASE+'login'):return self._denied()
        async with self.lock:
            self._prune()
            if self._browser(request):return self._redirect(PUBLIC+BASE)
            if len(self.logins)>=256:return self._denied(503)
            nonce,cookie,verifier=secrets.token_urlsafe(32),secrets.token_urlsafe(32),secrets.token_urlsafe(32)
            state=STATE_PREFIX+nonce
            self.logins[state]={'cookie':_digest(cookie),'verifier':verifier,'pending_id':'home','expires_at':self.clock()+300}
        challenge=push_b64(hashlib.sha256(verifier.encode('ascii')).digest())
        response=self._redirect('https://github.com/login/oauth/authorize?'+urlencode({'client_id':self.client_id,
            'redirect_uri':PUBLIC+CALLBACK,'scope':'read:user','state':state,'code_challenge':challenge,'code_challenge_method':'S256'}))
        self._cookie(response,LOGIN_COOKIE,cookie,300)
        return response

    async def asset(self, request):
        name=request.url.path[len(BASE):]
        if not self._host_ok(request,BASE+name) or request.query_params:return self._denied(404)
        headers={**HEADERS,'Cache-Control':'no-cache','Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'"}
        if name=='manifest.webmanifest':return JSONResponse({'id':BASE,'name':'Reach Approvals','short_name':'Reach',
            'start_url':BASE,'scope':BASE,'display':'standalone','background_color':'#ffffff','theme_color':'#194eb4',
            'icons':[{'src':BASE+'icon.png','sizes':'192x192','type':'image/png','purpose':'any'}]},headers=headers,media_type='application/manifest+json')
        if name=='icon.png':return Response(push_icon(),media_type='image/png',headers=headers)
        if name in ('sw.js','app.js'):
            if name=='sw.js':headers['Service-Worker-Allowed']=BASE
            return Response(PUSH_SW if name=='sw.js' else PUSH_JS,media_type='application/javascript',headers=headers)
        return self._denied(404)

    async def snapshot(self):
        now=self.clock();events=[]
        for identifier,item in tuple(self.pending_feed().items()):
            if (not ID.fullmatch(identifier) or item.get('state')!='awaiting_owner_approval'
                    or item.get('closed') or item.get('binding',{}).get('subject')!=self.owner):continue
            try:
                view=await self.get_pending(identifier,self.owner)
                if not self._validate_view(view):continue
            except Exception:continue
            created=self.push_created.setdefault(identifier,now)
            events.append({'id':identifier,'vm_id':view['vm_id'],'expires_at':view['expires_at'],'created_at':created,'kind':'approval','device':''})
        active={v['id'] for v in events};self.push_created={k:v for k,v in self.push_created.items() if k in active}
        self.push_tests={k:v for k,v in self.push_tests.items() if v['expires_at']>now}
        return (events+list(self.push_tests.values()))[:64]

    async def publish_feed(self):
        self.push_files.settings(self.owner)
        self.push_files.write('events.json',{'updated_at':self.clock(),'events':await self.snapshot()})

    async def run_feed(self):
        while True:
            try:await self.publish_feed()
            except Exception:pass
            await asyncio.sleep(5)

    async def home(self,request):
        if not self._host_ok(request,BASE) or request.query_params:return self._denied(404)
        signed=self._browser(request) is not None
        body='<p>Review administrator requests and receive phone alerts.</p>'
        body+='<p>On iPhone: open this page in Safari, choose Share → Add to Home Screen, then open the Reach icon.</p>'
        if not signed:body+='<p><a href="'+BASE+'login?pending=home">Sign in with GitHub</a></p>'
        else:
            body+='<h2>Notifications on this device</h2><p id="notification-status" role="status">Checking notification support…</p>'
            body+='<button id="enable" data-push disabled>Enable notifications</button><button id="test" data-push disabled>Send test notification</button><button id="disable" data-push disabled>Disable on this device</button>'
            body+='<h2>Waiting for your approval</h2>'
            events=[v for v in await self.snapshot() if v['kind']=='approval']
            body+='<ul>'+''.join('<li><a href="'+BASE+v['id']+'">Review '+_escape(v['vm_id'])+'</a></li>' for v in events)+'</ul>' if events else '<p>No administrator requests are waiting.</p>'
            body+='<p><a href="'+BASE+'">Refresh requests</a></p><p>Alerts open the review page. Only your choice on the review page grants or denies permission.</p><script src="'+BASE+'app.js" defer></script>'
        response=self._page('Reach Approvals',body)
        response.body=response.body.replace(b'</head>',('<link rel="manifest" href="'+BASE+'manifest.webmanifest"><link rel="apple-touch-icon" href="'+BASE+'icon.png"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="theme-color" content="#194eb4"></head>').encode())
        response.headers['content-length']=str(len(response.body))
        response.headers['Content-Security-Policy']=HEADERS['Content-Security-Policy']+"; script-src 'self'; worker-src 'self'; connect-src 'self'; manifest-src 'self'; img-src 'self'"
        return response

    async def push_config(self,request):
        if not self._host_ok(request,BASE+'push/config') or request.query_params or not self._browser(request):return self._denied()
        try:settings=self.push_files.settings(self.owner)
        except Exception:return JSONResponse({'error':'Notification storage is unavailable.'},status_code=503,headers=HEADERS)
        now=self.clock();self.push_forms={k:v for k,v in self.push_forms.items() if v['expires']>now}
        if len(self.push_forms)>=256:return self._denied(503)
        token=secrets.token_urlsafe(32)
        self.push_forms[_digest(token)]={'browser':self._browser(request),'expires':now+600}
        delivery=self.push_files.read('delivery.json',{})
        return JSONResponse({'csrf':token,'public_key':push_public(settings),'device_count':len(settings['devices']),
            'delivery_worker_recent':0<=now-delivery.get('updated_at',0)<=60},headers=HEADERS)

    async def push_action(self,request):
        action=request.path_params.get('action')
        if (action not in ('subscribe','unsubscribe','test') or not self._host_ok(request,BASE+'push/'+action)
                or request.query_params or request.headers.getlist('origin') != [PUBLIC]
                or request.headers.getlist('sec-fetch-site') not in ([],['same-origin'])
                or request.headers.getlist('content-type') != ['application/json']):return self._denied()
        browser=self._browser(request);tokens=request.headers.getlist('x-reach-csrf')
        token=tokens[0] if len(tokens)==1 else ''
        proof=self.push_forms.get(_digest(token)) if TOKEN.fullmatch(token) else None
        if not browser or not proof or proof['browser']!=browser or proof['expires']<=self.clock():return self._denied()
        raw=bytearray()
        async for part in request.stream():
            raw.extend(part)
            if len(raw)>8192:return self._denied(413)
        try:
            def unique(pairs):
                value=dict(pairs)
                if len(value)!=len(pairs):raise ValueError('Duplicate field.')
                return value
            data=json.loads(raw,object_pairs_hook=unique)
            settings=self.push_files.settings(self.owner)
            if action=='subscribe':
                if type(data) is not dict or set(data)!={'subscription'}:raise ValueError('Invalid subscription request.')
                sub=push_subscription(data['subscription']);identifier=_digest(sub['endpoint'])
                if identifier not in settings['devices'] and len(settings['devices'])>=8:raise ValueError('Eight devices are already registered.')
                settings['devices'][identifier]=sub;self.push_files.write('settings.json',settings)
            else:
                if type(data) is not dict or set(data)!={'endpoint'} or not isinstance(data['endpoint'],str) or len(data['endpoint'])>2048:raise ValueError('Invalid device request.')
                identifier=_digest(data['endpoint'])
                if action=='unsubscribe':
                    settings['devices'].pop(identifier,None);self.push_files.write('settings.json',settings)
                else:
                    if identifier not in settings['devices']:raise ValueError('Enable notifications on this device first.')
                    if any(v['device']==identifier and self.clock()-v['created_at']<30 for v in self.push_tests.values()):raise ValueError('Wait 30 seconds before sending another test.')
                    test=secrets.token_hex(16);self.push_tests[test]={'id':test,'vm_id':'test','kind':'test','device':identifier,'created_at':self.clock(),'expires_at':self.clock()+120}
            await self.publish_feed()
            return JSONResponse({'ok':True},headers=HEADERS)
        except (ValueError,UnicodeError,TypeError,KeyError):return JSONResponse({'error':'Invalid or unsupported notification request. Refresh the page and try again.'},status_code=400,headers=HEADERS)
        except OSError:return JSONResponse({'error':'Notification storage is unavailable.'},status_code=503,headers=HEADERS)


class SessionApprovalPortal(NotifyingApprovalPortal):
    """Owner-only management of Reach administrator grants; never a grant API."""
    def __init__(self, *args, list_sessions, revoke_sessions, **kwargs):
        super().__init__(*args, **kwargs)
        self.list_admin_sessions = list_sessions
        self.revoke_admin_sessions = revoke_sessions
        self.management_forms = {}

    def routes(self):
        return [Route(BASE+'sessions/revoke', self.revoke, methods=['POST']), *super().routes()]

    def management_form(self, browser, scope, label):
        now = self.clock()
        self.management_forms = {k:v for k,v in self.management_forms.items() if v['expires_at'] > now}
        if len(self.management_forms) >= 1024:
            raise PortalUnavailable()
        csrf = secrets.token_urlsafe(32)
        self.management_forms[_digest(csrf)] = {'browser':browser, 'scope':scope,
            'expires_at':min(now+300, self.sessions[browser]['expires_at'])}
        return ('<form method="post" action="'+BASE+'sessions/revoke">'
            '<input type="hidden" name="csrf" value="'+csrf+'">'
            '<input type="hidden" name="scope" value="'+scope+'">'
            '<button type="submit">'+_escape(label)+'</button></form>')

    async def session_panel(self, browser):
        panel = '<h2>Administrator sessions</h2>'
        try:
            value = await self.list_admin_sessions(self.owner)
            if type(value) is not dict or value.get('ok') is not True or type(value.get('sessions')) is not list or len(value['sessions']) > 256:
                raise PortalUnavailable()
            rows = value['sessions']
            for row in rows:
                if (type(row) is not dict or not isinstance(row.get('scope'), str)
                        or not re.fullmatch('[a-f0-9]{64}', row['scope'])
                        or not isinstance(row.get('session_id'), str) or not ID.fullmatch(row['session_id'])
                        or not isinstance(row.get('vm_id'), str) or not re.fullmatch('[a-z0-9-]{1,64}', row['vm_id'])
                        or row.get('permission_mode') not in ('workflow', 'ask_each')
                        or type(row.get('verified')) is not bool or type(row.get('ended')) is not bool
                        or type(row.get('jobs_in_progress')) is not int or not 0 <= row['jobs_in_progress'] <= 1024
                        or type(row.get('expires_at')) not in (int,float) or not math.isfinite(row['expires_at'])):
                    raise PortalUnavailable()
            # The all button is available even when no active grant is listed: it
            # also invalidates approvals that were opened on another device.
            panel += self.management_form(browser, 'all', 'Revoke all Reach admin permissions')
            if not rows:
                panel += '<p>No Reach administrator sessions are active.</p>'
            for row in rows:
                status = ('Ended' if row['ended'] else 'Verification unavailable' if not row['verified']
                          else 'Session permission active' if row['permission_mode'] == 'workflow'
                          else 'Approval required for each operation')
                remaining = max(0, int(row['expires_at']-self.clock()))
                panel += ('<section><h3>'+_escape(row['vm_id'])+'</h3><p>Session '
                    +_escape(row['session_id'][:8])+' · '+status+'</p>'
                    '<p>'+str(row['jobs_in_progress'])+' command(s) in progress. '
                    +'Current reservation expires in '+str(remaining//60)+'m '+str(remaining%60)+'s; the agent may renew it.</p>')
                if not row['ended']:
                    panel += self.management_form(browser, row['scope'], 'Revoke this session')
                panel += '</section>'
            panel += ('<p>Revoke stops further administrator work under the current permission and cancels waiting approvals. '
                'The session returns to approval for each operation. Commands already admitted may finish. '
                'Ordinary VM access stays available.</p><p><a href="'+BASE+'">Refresh sessions</a></p>')
        except Exception:
            panel += '<p>Administrator session status is unavailable. Refresh to retry; this page has not changed any permission.</p>'
        return panel

    async def home(self, request):
        response = await super().home(request)
        browser = self._browser(request)
        marker = b'<h2>Notifications on this device</h2>'
        if response.status_code == 200 and browser and marker in response.body:
            panel = await self.session_panel(browser)
            response.body = response.body.replace(marker, panel.encode('utf-8')+marker, 1)
            response.headers['content-length'] = str(len(response.body))
        return response

    async def revoke(self, request):
        if (not self._host_ok(request, BASE+'sessions/revoke') or request.query_params
                or request.headers.getlist('origin') != [PUBLIC]
                or request.headers.getlist('sec-fetch-site') not in ([], ['same-origin'])
                or len(request.headers.getlist('content-type')) != 1
                or request.headers['content-type'].split(';',1)[0].strip().lower() != 'application/x-www-form-urlencoded'):
            return self._denied()
        browser = self._browser(request)
        if browser is None:
            return self._denied()
        raw = bytearray()
        async for part in request.stream():
            raw.extend(part)
            if len(raw) > 4096:
                return self._denied(413)
        try:
            pairs = parse_qsl(raw.decode('ascii'), keep_blank_values=True, strict_parsing=True)
            data = dict(pairs)
            if (len(pairs) != 2 or set(data) != {'csrf','scope'} or not TOKEN.fullmatch(data['csrf'])
                    or (data['scope'] != 'all' and not re.fullmatch('[a-f0-9]{64}',data['scope']))):
                return self._denied(400)
        except (ValueError,UnicodeError):
            return self._denied(400)
        async with self.lock:
            proof = self.management_forms.get(_digest(data['csrf']))
            if (self._browser(request) != browser or not proof or proof['browser'] != browser
                    or proof['scope'] != data['scope'] or proof['expires_at'] <= self.clock()):
                return self._denied(409)
            del self.management_forms[_digest(data['csrf'])]
        try:
            result = await self.revoke_admin_sessions(self.owner, data['scope'])
            if (type(result) is not dict or result.get('ok') is not True
                    or result.get('durable_reduction_accepted') is not True):
                raise PortalUnavailable()
        except Exception:
            return self._page('Revocation not confirmed', '<p>Reach could not confirm the complete revocation. '
                'No permission was granted. <a href="'+BASE+'">Refresh the session list</a> and retry Revoke if needed. '
                'This retries only revocation, never an administrator command.</p>', 503)
        return self._page('Reach administrator permission revoked', '<p>Further administrator work needs a new approval. '
            'Commands already admitted may finish. <a href="'+BASE+'">Return to Reach Approvals</a>.</p>')
