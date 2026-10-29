"""Owner GitHub OAuth edge for exactly the pinned Nexus standard-user Reach tools."""
from contextlib import asynccontextmanager
import asyncio
import json
from copy import deepcopy
import re
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token, get_context
from fastmcp.server.auth.providers.github import GitHubProvider, GitHubTokenVerifier
from fastmcp.server.providers.base import Provider
from fastmcp.tools import Tool
from fastmcp.tools.base import ToolResult, InputRequiredToolResult
from mcp.types import CallToolResult, TextContent, ToolAnnotations, InputRequiredResult
from pydantic import PrivateAttr
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.routing import Route

from channel import ChannelDenied, WorkflowBusy, EXPOSED_TOOLS, MAX_REQUEST, loads, validate_request, validate_catalog
from public_limits import PublicBodyLimit
from admin_frontend import (ADMIN_TOOLS, AdminUnavailable, ReachAdminFrontend, admin_catalog,
    NegotiationLog, approval_transport, install_form_metadata, validate_admin_call)
from approval_portal import SessionApprovalPortal

PUBLIC = 'https://reach.example.invalid'
PREFIX = '/auth/callback/reach/nexus'
RESOURCE = '/reach/nexus/mcp'
METHODS = frozenset({'initialize','server/discover','notifications/initialized','ping','tools/list','tools/call'})
READ_ONLY = frozenset({'reach_get_screen_info','reach_screenshot','reach_list_windows','reach_get_cursor_position',
    'reach_get_clipboard','reach_wait','reach_get_capabilities','reach_list_directory','reach_read_file',
    'reach_search_files','reach_read_process','reach_list_processes','reach_admin_status'})
CLIENT_REDIRECTS = ['https://claude.ai/api/mcp/auth_callback','https://claude.com/api/mcp/auth_callback',
    'https://chatgpt.com/connector_platform_oauth_redirect','https://chatgpt.com/connector/oauth/*',
    'http://localhost:*/*','http://127.0.0.1:*/*']
DISCOVERY_TOOLS = frozenset({'reach_list_vms', 'reach_vm_status'})
RESERVATION_TOOLS = frozenset({'reach_claim_vm','reach_renew_vm_claim','reach_release_vm'})
PUBLIC_TOOLS = EXPOSED_TOOLS | DISCOVERY_TOOLS | RESERVATION_TOOLS | ADMIN_TOOLS
VM_ID = {'type':'string','pattern':'^[a-z0-9][a-z0-9-]{0,63}$',
         'description':'Required stable enrolled VM identity from reach_list_vms; never inferred.'}
WORKFLOW_TOKEN = {'type':'string','pattern':'^[A-Za-z0-9_-]{43}$','writeOnly':True,
    'description':'Secret returned only by reach_claim_vm for this workflow and VM. Never share or log it.'}
TTL = {'type':'integer','minimum':1,'maximum':600,'default':600,
    'description':'Explicit workflow reservation duration; renew the workflow claim when needed.'}
INSTRUCTIONS = (
    'Control only explicitly named, authorized Windows VMs using vm_id on every targeted call. '
    'Call reach_list_vms for authorized targets and reach_vm_status before acting. '
    'Claim the VM with reach_claim_vm for each independent workflow, keep its workflow_token private, '
    'and supply it on every native tool including file reads and process operations. '
    'A claim is exclusive for that VM; a busy VM must not be taken over or substituted. '
    'Wait for reservation phase ready before acting; renew explicitly and release when finished. '
    'Each handoff destroys the old native process context after authenticated worker acknowledgment. '
    'Different VMs may be used in parallel. Workflow tokens are possession-bound to the authorized OAuth owner, '
    'not inferred conversation identities; sharing a token shares that workflow. '
    'After timeout or request cancellation, discard the workflow token and wait for draining to finish. '
    'There is no selected VM or default. An unavailable target is never substituted. '
    'OAuth sign-in and worker enrollment do not activate desktop authority; each VM needs owner authorization. '
    'A persistent owner authorization has no expiration and automatically maintains internal session leases; '
    'its owner does not need to renew it. Workflow reservations remain short and exclusive. '
    'Screens, clipboard, selected files and command output are visible to the model provider. '
    'Observe, act, verify. Commands have the standard Windows user permissions; file roots do not sandbox commands. '
    'Never unlock Windows, enter passwords, bypass UAC, change approval controls or invoke another AI to execute tools. '
    'A timeout or interruption may have partially completed: inspect before deciding to repeat. '
    'Administrator requests may return an owner approval link and a pending job identifier. '
    'Show that exact link to the owner; opening it or signing in is not approval. '
    'Keep and explicitly renew the same VM reservation while waiting, and poll reach_admin_status '
    'with that same identifier; do not resubmit the command or release its reservation before a terminal result. '
    'A locked, signed-out or unavailable desktop requires a separate owner-managed Windows session. '
    'Owner pause and failsafe remain enabled. Windows is the currently supported worker platform.'
)


def subject():
    token = get_access_token()
    identity = getattr(token, 'subject', None)
    if not isinstance(identity, str) or not identity:
        raise ChannelDenied()
    return identity


def validate_public_call(name, arguments):
    if name not in PUBLIC_TOOLS or type(arguments) is not dict:
        raise ChannelDenied()
    if name == 'reach_list_vms':
        if arguments:
            raise ChannelDenied()
        return
    if name in ADMIN_TOOLS:
        validate_admin_call(name, arguments)
        return
    vm_id = arguments.get('vm_id')
    if not isinstance(vm_id,str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',vm_id):
        raise ChannelDenied()
    native = {key:value for key,value in arguments.items() if key != 'vm_id'}
    if name == 'reach_vm_status':
        if native:
            raise ChannelDenied()
    elif name in RESERVATION_TOOLS:
        required = {'workflow_token'} if name != 'reach_claim_vm' else set()
        allowed = required | ({'ttl_seconds'} if name != 'reach_release_vm' else set())
        if not required <= set(native) or not set(native) <= allowed:
            raise ChannelDenied()
        if 'workflow_token' in native and (not isinstance(native['workflow_token'],str)
                or not re.fullmatch(r'[A-Za-z0-9_-]{43}',native['workflow_token'])):
            raise ChannelDenied()
        ttl = native.get('ttl_seconds',600)
        if type(ttl) is not int or not 1 <= ttl <= 600:
            raise ChannelDenied()
    else:
        token = native.pop('workflow_token',None)
        if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',token):
            raise ChannelDenied()
        validate_request('tools/call',{'name':name,'arguments':native})




def denied(status=403):
    return JSONResponse({'error':str(ChannelDenied())},status_code=status,headers={'Cache-Control':'no-store'})


class ReachTool(Tool):
    _channel: object = PrivateAttr()
    _admin: object = PrivateAttr(default=None)

    @classmethod
    def wrap(cls, value, channel, admin=None):
        name = value['name']
        readonly = name in READ_ONLY or name in DISCOVERY_TOOLS
        schema = deepcopy(value['inputSchema'])
        if name != 'reach_list_vms':
            schema.setdefault('properties', {})['vm_id'] = deepcopy(VM_ID)
            schema['required'] = list(dict.fromkeys([*schema.get('required', []), 'vm_id']))
        if name in EXPOSED_TOOLS:
            schema.setdefault('properties', {})['workflow_token'] = deepcopy(WORKFLOW_TOKEN)
            schema['required'] = list(dict.fromkeys([*schema.get('required', []), 'workflow_token']))
        tool = cls(name=name, description=value.get('description','')[:12000],
            parameters=schema, annotations=ToolAnnotations(readOnlyHint=readonly,
            destructiveHint=not readonly, idempotentHint=readonly,
            openWorldHint=name in {'reach_run_command','reach_launch_application'}))
        tool._channel = channel
        tool._admin = admin
        return tool

    async def run(self, arguments):
        try:
            validate_public_call(self.name, arguments)
            owner = subject()
            if self.name in ADMIN_TOOLS:
                value = await self._admin.run(self.name, arguments, owner, get_context())
                if isinstance(value, InputRequiredResult):
                    return InputRequiredToolResult(input_required=value)
                return ToolResult(content=[TextContent(type='text',text=json.dumps(value))], structured_content=value)
            if self.name in DISCOVERY_TOOLS:
                vms = self._channel.discovery(owner)
                if self.name == 'reach_vm_status':
                    vms = [vm for vm in vms if vm['vm_id'] == arguments['vm_id']]
                    if len(vms) != 1:
                        raise ChannelDenied()
                    value = vms[0]
                else:
                    value = {'vms':vms}
                return ToolResult(content=[TextContent(type='text',text=json.dumps(value))],
                    structured_content=value)
            if self.name in RESERVATION_TOOLS:
                self._channel.registry.assert_epoch(self._channel.epoch)
                registry = self._channel.registry
                if self.name == 'reach_claim_vm':
                    value = registry.claim(arguments['vm_id'],owner,arguments.get('ttl_seconds',600))
                elif self.name == 'reach_renew_vm_claim':
                    value = registry.renew_claim(arguments['vm_id'],owner,arguments['workflow_token'],arguments.get('ttl_seconds',600))
                    try:
                        await self._admin.renew(self._admin.binding(owner, arguments, ready=False))
                    except AdminUnavailable:
                        value['admin_service_renew_acknowledged'] = False
                else:
                    binding = self._admin.binding(owner, arguments, ready=False)
                    value = registry.release_claim(arguments['vm_id'],owner,arguments['workflow_token'])
                    try:
                        await self._admin.end(binding)
                    except AdminUnavailable:
                        # Registry control/epoch fencing immediately forbids new
                        # dispatch even when the separate owner broker is down.
                        value['admin_service_end_acknowledged'] = False
                return ToolResult(content=[TextContent(type='text',text=json.dumps(value))],structured_content=value)
            native = {key:value for key,value in arguments.items() if key not in {'vm_id','workflow_token'}}
            value = await self._channel.request(self.name, native, arguments['vm_id'], owner, arguments['workflow_token'])
            result = CallToolResult.model_validate(value)
            if self.name == 'reach_get_capabilities' and not result.is_error:
                # Observe the actual authenticated call's negotiated transport
                # without preparing work or contacting the administrator broker.
                # A usable approval transport is never an administrator grant.
                transport, reason, observed = approval_transport(get_context())
                diagnostic = {'selected_transport': transport, 'refusal': reason,
                    'observed': observed, 'administrator_permission_granted': False,
                    'owner_approval_link_available': bool(getattr(self._admin, 'portal_enabled', False))}
                return ToolResult(content=[*result.content,
                    TextContent(type='text', text=json.dumps({'gateway_admin_approval': diagnostic}))],
                    structured_content={**(result.structured_content or {}),
                        'gateway_admin_approval': diagnostic}, is_error=result.is_error)
            return ToolResult(content=result.content, structured_content=result.structured_content, is_error=result.is_error)
        except AdminUnavailable as error:
            return ToolResult(content=[TextContent(type='text',text=str(error))],is_error=True)
        except WorkflowBusy as error:
            return ToolResult(content=[TextContent(type='text',text=str(error))],is_error=True)
        except Exception:
            return ToolResult(content=[TextContent(type='text',text=str(ChannelDenied()))],is_error=True)


class ReachProvider(Provider):
    def __init__(self, channel, catalog, admin=None):
        super().__init__()
        self.channel = channel
        self.catalog = validate_catalog(catalog)
        self.admin = admin or ReachAdminFrontend(channel)

    async def _list_tools(self):
        values = list(self.catalog['tools']) + [
            {'name':'reach_list_vms','description':'List authorized VM identities, connectivity, desktop status and owner authorization mode. Persistent authorization has no expiration; lease_expires_at is an automatically maintained internal session bound. Enrollment and OAuth do not grant desktop access.',
             'inputSchema':{'type':'object','properties':{},'additionalProperties':False}},
            {'name':'reach_vm_status','description':'Read status of one explicitly named authorized VM without activating it.',
             'inputSchema':{'type':'object','properties':{},'additionalProperties':False}}]
        values.extend([
            {'name':'reach_claim_vm','description':'Reserve one owner-authorized VM exclusively for a workflow. Returns its secret once, or busy status. Does not activate desktop authority. Wait for ready; default TTL 600 seconds.',
             'inputSchema':{'type':'object','properties':{'ttl_seconds':deepcopy(TTL)},'additionalProperties':False}},
            {'name':'reach_renew_vm_claim','description':'Explicitly renew this workflow reservation, within its current owner lease. Never resurrects expired claims.',
             'inputSchema':{'type':'object','properties':{'workflow_token':deepcopy(WORKFLOW_TOKEN),'ttl_seconds':deepcopy(TTL)},'required':['workflow_token'],'additionalProperties':False}},
            {'name':'reach_release_vm','description':'Release this exact workflow. Its native processes and handles are closed before another workflow may act. Late results and reuse are refused.',
             'inputSchema':{'type':'object','properties':{'workflow_token':deepcopy(WORKFLOW_TOKEN)},'required':['workflow_token'],'additionalProperties':False}}])
        values.extend(admin_catalog())
        return [ReachTool.wrap(tool,self.channel,self.admin) for tool in values]

    async def _get_tool(self, name, version=None):
        if name not in PUBLIC_TOOLS:
            return None
        return next((tool for tool in await self._list_tools() if tool.name == name), None)


class OwnerOnlyVerifier(GitHubTokenVerifier):
    def __init__(self, owner, **kwargs):
        super().__init__(**kwargs)
        self.owner = str(owner)

    async def verify_token(self, token):
        value = await super().verify_token(token)
        return value if value and value.subject == self.owner else None


class RPCGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope.get('path') != '/mcp':
            return await self.app(scope,receive,send)
        if scope.get('query_string') or scope['method'] not in {'GET','POST','DELETE'}:
            return await denied()(scope,receive,send)
        if scope['method'] != 'POST':
            return await self.app(scope,receive,send)
        raw = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            raw.extend(message.get('body',b''))
            if len(raw) > MAX_REQUEST:
                return await denied(413)(scope,receive,send)
            if not message.get('more_body'):
                break
        sent = False
        async def replay():
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {'type':'http.request','body':bytes(raw),'more_body':False}
        try:
            if raw:
                value = loads(bytes(raw))
                if (type(value) is not dict or not set(value) <= {'jsonrpc','id','method','params'}
                        or value.get('jsonrpc') != '2.0' or value.get('method') not in METHODS):
                    raise ChannelDenied()
                identity = value.get('id')
                if identity is not None and type(identity) not in (str,int):
                    raise ChannelDenied()
                if isinstance(identity,str) and (len(identity)>256 or any(ord(c)<32 for c in identity)):
                    raise ChannelDenied()
                params = value.get('params',{})
                if type(params) is not dict:
                    raise ChannelDenied()
                if value['method'] == 'tools/call':
                    allowed = {'name','arguments','_meta'}
                    if params.get('name') in ADMIN_TOOLS:
                        allowed |= {'inputResponses','requestState'}
                    if (not set(params) <= allowed or ('_meta' in params and type(params['_meta']) is not dict)
                            or ('inputResponses' in params and type(params['inputResponses']) is not dict)
                            or ('requestState' in params and (not isinstance(params['requestState'],str)
                                or len(params['requestState']) > 16384))):
                        raise ChannelDenied()
                    validate_public_call(params.get('name'), params.get('arguments',{}))
        except (ChannelDenied,TypeError,ValueError):
            return await denied()(scope,receive,send)
        return await self.app(scope,replay,send)


class ExactEndpoint:
    def __init__(self, app, path):
        self.app,self.path = app,path

    async def __call__(self, scope, receive, send):
        path = scope.get('path','')
        try:
            if scope.get('raw_path',path.encode('ascii')) != path.encode('ascii'):
                raise ChannelDenied()
        except (ChannelDenied,UnicodeError):
            return await denied(404)(scope,receive,send)
        return await self.app({**scope,'path':self.path,'raw_path':self.path.encode(),'root_path':''},receive,send)


class OwnerCallbackMux:
    """Only the reserved browser state prefix goes to the owner-page callback."""
    def __init__(self, app, portal):
        self.original = ExactEndpoint(app, '/auth/callback')
        self.portal = portal

    async def __call__(self, scope, receive, send):
        expected = (PREFIX + '/auth/callback').encode('ascii')
        try:
            raw = scope.get('raw_path')
            if raw is None:
                raw = scope['path'].encode('ascii')
        except (UnicodeError, KeyError):
            return await denied(404)(scope, receive, send)
        if raw != expected:
            return await denied(404)(scope, receive, send)
        request = Request(scope, receive)
        # Inspect every occurrence: a duplicated reserved state must fail in the
        # portal handler, never fall through into the existing MCP OAuth flow.
        if any(self.portal.is_portal_state(value) for value in request.query_params.getlist('state')):
            response = await self.portal.handle_callback(request)
            return await response(scope, receive, send)
        return await self.original(scope, receive, send)


def create_app(config, channel, catalog=None):
    if type(config) is not dict or set(config) != {'oauth_config','oauth_key'}:
        raise ValueError('Invalid reviewed OAuth configuration.')
    oauth = config['oauth_config']
    ids = oauth.get('allowed_github_user_ids')
    if oauth.get('public_url') != PUBLIC or type(ids) is not list or len(ids) != 1 or type(ids[0]) is not int or ids[0] <= 0:
        raise ValueError('The exact Nexus authority and immutable owner ID are required.')
    for value in (oauth.get('client_id'),oauth.get('client_secret'),config.get('oauth_key')):
        if not isinstance(value,str) or len(value)<20 or value.startswith('PASTE'):
            raise ValueError('Independent OAuth configuration is required.')
    auth = GitHubProvider(client_id=oauth['client_id'],client_secret=oauth['client_secret'],base_url=PUBLIC+PREFIX,
        resource_base_url=PUBLIC+'/reach/nexus',issuer_url=PUBLIC+PREFIX,redirect_path='/auth/callback',
        required_scopes=['read:user'],allowed_client_redirect_uris=CLIENT_REDIRECTS,
        jwt_signing_key=config['oauth_key'],require_authorization_consent=True,cache_ttl_seconds=300,
        fastmcp_access_token_expiry_seconds=3600,enable_cimd=False)
    auth._token_validator = OwnerOnlyVerifier(ids[0],required_scopes=['read:user'],cache_ttl_seconds=300)
    if catalog is None:
        catalog = loads(Path(__file__).with_name('tool-catalog.json').read_bytes(),262144)
    admin = ReachAdminFrontend(channel, diagnostics=NegotiationLog(), portal_enabled=True)
    portal = SessionApprovalPortal(config, list_sessions=admin.admin_sessions, revoke_sessions=admin.revoke_sessions, get_pending=admin.portal_get, pending_feed=lambda: admin.portal_entries,
        decide_pending=admin.portal_decide, transport_scheme='http')
    server = FastMCP('Reach MCP (Nexus Gateway)',instructions=INSTRUCTIONS,providers=[ReachProvider(channel,catalog,admin)],auth=auth)
    install_form_metadata(server)
    app = server.http_app(path='/mcp',stateless_http=True,json_response=True,
        allowed_hosts=['reach.example.invalid','127.0.0.1','127.0.0.1:18885'],
        allowed_origins=[PUBLIC],host_origin_protection='auto')
    routes = [Route(RESOURCE,ExactEndpoint(RPCGuard(app),'/mcp'),methods=['POST','GET','DELETE']),
        *portal.routes()]
    for path,methods in (('/authorize',['GET','POST']),('/token',['POST','OPTIONS']),('/register',['POST','OPTIONS']),
            ('/consent',['GET','POST']),('/auth/callback',['GET'])):
        endpoint = OwnerCallbackMux(app, portal) if path == '/auth/callback' else ExactEndpoint(app, path)
        routes.append(Route(PREFIX+path, endpoint, methods=methods))
    for kind in ('oauth-authorization-server','openid-configuration'):
        routes.append(Route('/.well-known/'+kind+PREFIX,ExactEndpoint(app,'/.well-known/oauth-authorization-server'),methods=['GET','OPTIONS']))
    protected = '/.well-known/oauth-protected-resource'+RESOURCE
    routes.append(Route(protected,ExactEndpoint(app,protected),methods=['GET','OPTIONS']))
    @asynccontextmanager
    async def lifespan(_):
        async with app.lifespan(app):
            push_task = asyncio.create_task(portal.run_feed())
            reduction_task = asyncio.create_task(admin.reduction_loop())
            try:
                yield
            finally:
                reduction_task.cancel()
                try:
                    await reduction_task
                except asyncio.CancelledError:
                    pass
                push_task.cancel()
                try:
                    await push_task
                except asyncio.CancelledError:
                    pass
    result = Starlette(routes=routes,lifespan=lifespan)
    result.router.redirect_slashes = False
    result.add_middleware(PublicBodyLimit)
    return result


def load_config():
    return loads(Path('/run/secrets/oauth.json').read_bytes(),16384)
