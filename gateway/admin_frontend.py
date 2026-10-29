"""Human-approved VM administration through a private Nexus owner broker.

The public schema never accepts an approval. MCP elicitation responses are
transport context, and only a framework-sealed continuation can consume a
captured operation. A grant belongs to one Reach workflow/control generation;
it is not a claim about the lifetime of an arbitrary chat conversation.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
import base64
import hashlib
import json
import re
import os
import secrets
import time

from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from channel import ChannelDenied, encoded, loads

ADMIN_TOOLS = frozenset({'reach_run_admin', 'reach_revoke_admin', 'reach_admin_status'})
SOCKET_PATH = '/run/reach-owner-mcp/owner.sock'
IDENTITY_FIELDS = ('subject', 'vm_id', 'control_id', 'lease_id', 'gateway_epoch')
MAX_PENDING = 128
OPENAI_FORMS = 'openai/elicitation'
NEGOTIATION_LOG = '/state/reach-admin/negotiation.jsonl'
OWNER_APPROVAL_BASE = 'https://reach.example.invalid/reach/nexus/admin'
CHOICE_TEXT = {
    'once': ('Approve once', 'Run only this exact operation.'),
    'workflow': ('Approve for this workflow', 'Allow administrator operations for this Reach workflow until it is released, expires or you revoke.'),
    'deny': ('Deny', 'Do not run this operation.'),
}
REFUSALS = {
    'no_request_context': 'no MCP request context was available for this call',
    'handshake_protocol': 'the client negotiated a handshake-era MCP protocol; this stateless gateway delivers approval forms only through multi-round-trip requests',
    'no_capabilities': 'the client declared no capabilities for this request',
    'no_form_elicitation': 'the client did not declare form elicitation (missing, malformed or URL-only)',
    'form_metadata_unavailable': 'the gateway cannot deliver ChatGPT extended-form metadata on this server',
}
_form_schemas = ContextVar('reach_openai_form_schemas', default=None)


@contextmanager
def form_metadata_scope():
    """Collect extended-form schemas for one server request."""
    schemas = {}
    token = _form_schemas.set(schemas)
    try:
        yield schemas
    finally:
        _form_schemas.reset(token)


async def restore_form_metadata(ctx, call_next):
    """Low-level MCP middleware: the SDK's per-version result sieve drops
    _meta from embedded elicitation params; restore only forms this gateway
    created for this request (the approach of OpenAI's own Python extension)."""
    with form_metadata_scope() as schemas:
        result = await call_next(ctx)
    if isinstance(result, dict) and result.get('resultType') == 'input_required':
        for key, request in (result.get('inputRequests') or {}).items():
            if (key in schemas and isinstance(request, dict) and request.get('method') == 'elicitation/create'
                    and isinstance(request.get('params'), dict)):
                request['params'].setdefault('_meta', {})[OPENAI_FORMS] = {'requestedSchema': schemas[key]}
    return result


def install_form_metadata(server):
    """Attach restore_form_metadata to a FastMCP server's low-level runner."""
    chain = server._mcp_server.middleware
    if restore_form_metadata not in chain:
        chain.append(restore_form_metadata)


class AdminUnavailable(RuntimeError):
    pass


def validate_admin_call(name, value):
    if name not in ADMIN_TOOLS or type(value) is not dict:
        raise ChannelDenied()
    base = {'vm_id', 'workflow_token'}
    required = base | ({'script'} if name == 'reach_run_admin' else
                       {'job_id'} if name == 'reach_admin_status' else set())
    allowed = required | ({'arguments', 'timeout_seconds'} if name == 'reach_run_admin' else set())
    if not required <= set(value) or not set(value) <= allowed:
        raise ChannelDenied()
    if (not isinstance(value['vm_id'], str) or value['vm_id'] not in {'vm-alpha', 'vm-beta', 'vm-gamma'}
            or not isinstance(value['workflow_token'], str)
            or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value['workflow_token'])):
        raise ChannelDenied()
    if name == 'reach_admin_status':
        if not isinstance(value['job_id'], str) or not re.fullmatch('[a-f0-9]{32}', value['job_id']):
            raise ChannelDenied()
    if name != 'reach_run_admin':
        return
    script, arguments, timeout = value['script'], value.get('arguments', []), value.get('timeout_seconds', 60)
    if (not isinstance(script, str) or '\0' in script or not 0 < len(script.encode('utf-8')) <= 16384
            or type(arguments) is not list or len(arguments) > 32
            or any(not isinstance(a, str) or '\0' in a or len(a.encode('utf-8')) > 8192 for a in arguments)
            or sum(len(a.encode('utf-8')) for a in arguments) > 32768
            or type(timeout) is not int or not 1 <= timeout <= 300):
        raise ChannelDenied()


class UnixOwnerBroker:
    """Only this one socket is mounted in the unprivileged gateway container."""
    def __init__(self, path=SOCKET_PATH):
        if path != SOCKET_PATH:
            raise ValueError('The fixed Nexus owner broker socket is required.')
        self.path = path

    async def request(self, value):
        writer = None
        try:
            async with asyncio.timeout(30):
                reader, writer = await asyncio.open_unix_connection(self.path, limit=262145)
                writer.write(encoded(value) + b'\n')
                await writer.drain()
                writer.write_eof()
                raw = await reader.readline()
                if not raw.endswith(b'\n'):
                    raise ChannelDenied()
                result = loads(raw, 262144)
                if type(result) is not dict or result.get('ok') is not True:
                    raise ChannelDenied()
                return result
        except (OSError, ValueError, TimeoutError, ChannelDenied, AttributeError, NotImplementedError):
            raise AdminUnavailable('The private Nexus administrator service is unavailable; no automatic retry was made.') from None
        finally:
            if writer is not None:
                writer.close()
                try:
                    async with asyncio.timeout(2):
                        await writer.wait_closed()
                except (OSError, TimeoutError):
                    pass


def _same(a, b):
    return all(a.get(key) == b.get(key) for key in IDENTITY_FIELDS)


def _plain(value):
    if hasattr(value, 'model_dump'):
        value = value.model_dump(by_alias=True, exclude_none=True)
    return value


def _names(value, limit=16):
    return sorted(str(key)[:64] for key in value)[:limit] if isinstance(value, dict) else None


def _key_types(value, limit=16):
    return {str(key)[:64]: type(value[key]).__name__[:32] for key in sorted(value, key=str)[:limit]} if isinstance(value, dict) else None


def approval_transport(ctx):
    """Use negotiated per-request capability, never an agent tool argument.

    Returns (transport, reason, observed). transport is 'openai' (ChatGPT
    extended forms), 'standard' (MCP form elicitation) or None with a refusal
    reason. observed holds only non-secret negotiation shape for diagnostics.
    """
    request = getattr(ctx, 'request_context', None)
    version = getattr(request, 'protocol_version', None)
    session = getattr(request, 'session', None)
    capabilities = _plain(getattr(session, 'client_capabilities', None))
    info = _plain(getattr(getattr(session, 'client_params', None), 'client_info', None))
    elicitation = capabilities.get('elicitation') if isinstance(capabilities, dict) else None
    extensions = capabilities.get('extensions') if isinstance(capabilities, dict) else None
    openai = extensions.get(OPENAI_FORMS) if isinstance(extensions, dict) else None
    observed = {'protocol_version': version[:32] if isinstance(version, str) else None,
        'capability_keys': _names(capabilities), 'elicitation_keys': _names(elicitation),
        'extension_keys': _names(extensions),
        'openai_elicitation_type': type(openai).__name__,
        'openai_elicitation_keys': _names(openai),
        'openai_elicitation_key_types': _key_types(openai),
        'openai_form_type': type(openai.get('form')).__name__ if isinstance(openai, dict) else None,
        'client': {key: str(info[key])[:64] for key in ('name', 'version') if key in info} if isinstance(info, dict) else None}
    if request is None:
        return None, 'no_request_context', observed
    # The SDK's own modern-era set, not a pinned date: an SDK update that adds
    # a revision is accepted only after this gateway's canary tests pass on it.
    if not isinstance(version, str) or version not in MODERN_PROTOCOL_VERSIONS:
        return None, 'handshake_protocol', observed
    if not isinstance(capabilities, dict):
        return None, 'no_capabilities', observed
    if type(elicitation) is not dict or (elicitation and type(elicitation.get('form')) is not dict):
        return None, 'no_form_elicitation', observed
    if type(openai) is dict and type(elicitation.get('form')) is dict:
        # Canonical SDK declaration: extensions[OPENAI_FORMS].form is {}.
        if type(openai.get('form')) is dict:
            return 'openai', None, observed
        # Bounded wire compatibility: an explicit true form flag. A namespace
        # object may advertise only user verification or other features, so
        # namespace presence alone never establishes extended-form support.
        # Native sealed acceptance is still required before dispatch.
        if openai.get('form') is True:
            observed['compatibility'] = 'openai_boolean_form'
            return 'openai', None, observed
    return 'standard', None, observed


def owner_page_needed(ctx, transport):
    """Use the independent owner page unless extended native forms are explicit."""
    return transport != 'openai'


def approval_form(transport, message, choices):
    """Build the elicitation for one transport; the answer schema is identical."""
    from mcp.types import ElicitRequest, ElicitRequestFormParams
    if transport == 'openai':
        # OpenAI extended forms: the core schema MUST be empty and the real
        # schema travels in _meta, otherwise ChatGPT reports it unsupported.
        schema = {'type': 'object', 'properties': {'choice': {'type': 'string', 'title': 'Administrator permission',
            'oneOf': [{'const': c, 'title': CHOICE_TEXT[c][0], 'description': CHOICE_TEXT[c][1]} for c in choices]}},
            'required': ['choice']}
        params = ElicitRequestFormParams(message=message, requested_schema={'type': 'object', 'properties': {}},
            _meta={OPENAI_FORMS: {'requestedSchema': schema}})
        schemas = _form_schemas.get()
        if schemas is not None:
            schemas['owner_admin'] = schema
    else:
        params = ElicitRequestFormParams(message=message, requested_schema={'type': 'object', 'properties': {
            'choice': {'type': 'string', 'enum': choices, 'default': 'deny', 'title': 'Administrator permission'}},
            'required': ['choice']})
    return ElicitRequest(method='elicitation/create', params=params)


class NegotiationLog:
    """Bounded, secret-free record of approval negotiation outcomes on Nexus state."""
    def __init__(self, path=NEGOTIATION_LOG, limit=262144):
        self.path, self.limit = path, limit

    def __call__(self, record):
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.limit:
                os.replace(self.path, self.path + '.1')
            with open(self.path, 'a', encoding='utf-8') as handle:
                handle.write(json.dumps({'utc': time.time(), **record}, separators=(',', ':')) + '\n')
        except (OSError, TypeError, ValueError):
            pass


class ReachAdminFrontend:
    def __init__(self, channel, broker=None, clock=time.time, diagnostics=None, portal_enabled=False):
        self.channel = channel
        self.broker = broker or UnixOwnerBroker()
        self.clock = clock
        # The gateway passes NegotiationLog(); fixtures default to no record.
        self.diagnostics = diagnostics or (lambda record: None)
        self.pending = {}
        self.tracked = set()
        self.portal_enabled = portal_enabled is True
        self.portal_entries = {}

    def binding(self, owner, arguments, ready=True):
        registry = self.channel.registry
        lease, row = registry.authorize_reservation(arguments['vm_id'], owner,
            self.channel.epoch, arguments['workflow_token'], ready=ready)
        return {'subject': owner, 'vm_id': arguments['vm_id'], 'control_id': row['control_id'],
            'lease_id': lease['lease_id'], 'gateway_epoch': row['gateway_epoch'], 'expires_at': row['expires_at']}

    def prune(self):
        now = self.clock()
        self.pending = {key: item for key, item in self.pending.items() if item['expires_at'] > now}
        for item in self.portal_entries.values():
            if item['expires_at'] <= now and not item.get('closed'):
                item['closed'] = 'expired'
                if item['state'] == 'awaiting_owner_approval':
                    item['state'] = 'expired'
        self.portal_entries = {key: item for key, item in self.portal_entries.items()
            if item['expires_at'] + 600 > now}

    def _close_portal(self, binding, reason):
        for item in self.portal_entries.values():
            if _same(item['binding'], binding):
                item['closed'] = reason
                if item['state'] == 'awaiting_owner_approval':
                    item['state'] = reason

    def _portal_item(self, request_id, owner):
        self.prune()
        item = self.portal_entries.get(request_id) if isinstance(request_id, str) else None
        if item is None or item['binding']['subject'] != owner:
            raise ChannelDenied()
        return item

    def _portal_live(self, item, owner):
        if item.get('closed') or item['expires_at'] <= self.clock():
            raise ChannelDenied()
        try:
            current = self.binding(owner, item['arguments'])
            if (not _same(current, item['binding'])
                    or item['arguments_sha256'] != hashlib.sha256(encoded(item['arguments'])).hexdigest()):
                raise ChannelDenied()
        except Exception:
            item['closed'] = 'unavailable'
            if item['state'] == 'awaiting_owner_approval':
                item['state'] = 'unavailable'
            raise ChannelDenied() from None

    def _portal_status(self, item):
        value = {'ok': True, 'state': item.get('closed') or item['state'],
            'job_id': item.get('job_id') or item['request_id'], 'approval_request_id': item['request_id'],
            'administrator_permission_granted': item.get('approved') is True,
            'automatic_retry': False, 'permission_mode': item.get('permission_mode', 'ask_each')}
        if value['state'] == 'awaiting_owner_approval':
            value['approval_url'] = OWNER_APPROVAL_BASE + '/' + item['request_id']
            value['detail'] = 'Open the owner approval page to review and approve this exact operation. Nothing has run.'
        elif value['state'] in {'dispatching', 'outcome_uncertain'}:
            value['detail'] = 'The approved operation may have started. It will not be submitted again.'
        return value

    def _start_owner_page(self, item, arguments, excluded=()):
        request_id = secrets.token_hex(16)
        forbidden = (item['operation_id'], item['approval_nonce'], *excluded)
        while request_id in self.portal_entries or request_id in self.pending or request_id in forbidden:
            request_id = secrets.token_hex(16)
        item.update(request_id=request_id, state='awaiting_owner_approval', approved=False,
            job_id=None, arguments=loads(encoded(arguments)), transport='owner_page')
        self.portal_entries[request_id] = item
        return self._portal_status(item)

    async def portal_get(self, request_id, owner):
        """Internal owner-browser callback; never exposed as an MCP tool."""
        item = self._portal_item(request_id, owner)
        if item.get('closed'):
            return {'state': item['closed']}
        self._portal_live(item, owner)
        if item['state'] != 'awaiting_owner_approval':
            return self._portal_status(item)
        arguments = item['arguments']
        return {'state': 'awaiting_owner', 'vm_id': item['binding']['vm_id'],
            'script': arguments['script'], 'arguments': list(arguments.get('arguments', [])),
            'timeout_seconds': arguments.get('timeout_seconds', 60),
            'request_sha256': item['request_sha256'], 'expires_at': item['expires_at'],
            'session_allowed': item['workflow_release_verified'], 'session_id': item['binding']['control_id']}

    async def admin_sessions(self, owner):
        """Owner-browser only. The broker supplies actual grants, never UI guesses."""
        return await self.broker.request({'version': 1, 'command': 'sessions', 'subject': owner})

    async def revoke_sessions(self, owner, scope):
        """Reduction only, after owner authentication and a browser-bound CSRF POST."""
        if scope != 'all' and (not isinstance(scope, str) or not re.fullmatch('[a-f0-9]{64}', scope)):
            raise ChannelDenied()
        def matches(item):
            binding = item['binding']
            key = hashlib.sha256(json.dumps([binding[k] for k in IDENTITY_FIELDS],
                separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
            return binding['subject'] == owner and (scope == 'all' or key == scope)
        # Invalidate old browser/native approvals before yielding to the broker.
        self.pending = {k:v for k,v in self.pending.items() if not matches(v)}
        for item in self.portal_entries.values():
            if matches(item) and item['state'] == 'awaiting_owner_approval':
                item['closed'] = item['state'] = 'revoked'
        return await self.broker.request({'version': 1, 'command': 'revoke-sessions',
            'subject': owner, 'scope': scope, 'reference': 'Owner revoked Reach administrator permission on the owner page'})

    async def portal_decide(self, request_id, owner, choice):
        """Called only after independent owner-browser authentication and CSRF POST."""
        if type(choice) is not str or choice not in {'once', 'workflow', 'deny'}:
            raise ChannelDenied()
        item = self._portal_item(request_id, owner)
        if item.get('closed'):
            return self._portal_status(item)
        self._portal_live(item, owner)
        if item['state'] != 'awaiting_owner_approval':
            return self._portal_status(item)
        if choice == 'workflow' and not item['workflow_release_verified']:
            raise ChannelDenied()
        # Consume synchronously before the first await: duplicate POSTs cannot
        # issue another execute, including after cancellation or uncertain I/O.
        if choice == 'deny':
            item['state'] = 'declined'
            return self._portal_status(item)
        item['state'] = 'dispatching'
        item['approved'] = True
        item['permission_mode'] = 'workflow' if choice == 'workflow' else 'once'
        try:
            result = await self.execute(item, item['arguments'], owner, choice,
                approval_reference='Reach owner page:' + request_id)
            job_id = result.get('job_id') if type(result) is dict else None
            if (result.get('ok') is not True or not isinstance(job_id, str)
                    or not re.fullmatch('[a-f0-9]{32}', job_id)):
                raise AdminUnavailable('Uncertain owner-approved dispatch.')
            item['job_id'] = job_id
            item['state'] = result.get('state') if isinstance(result.get('state'), str) else 'running'
        except asyncio.CancelledError:
            item['state'] = 'outcome_uncertain'
            raise
        except Exception:
            item['state'] = 'outcome_uncertain'
        return self._portal_status(item)

    async def _portal_poll(self, item, binding, owner):
        if not _same(binding, item['binding']):
            raise ChannelDenied()
        if item.get('closed'):
            return self._portal_status(item)
        self._portal_live(item, owner)
        if not item.get('job_id'):
            return self._portal_status(item)
        result = await self.broker.request({'version': 1, 'command': 'poll', 'binding': binding,
            'job_id': item['job_id']})
        if isinstance(result.get('state'), str):
            item['state'] = result['state']
        return {**result, 'approval_request_id': item['request_id']}

    async def end(self, binding, reference='Reach workflow released'):
        self.pending = {key: item for key, item in self.pending.items() if not _same(item['binding'], binding)}
        self._close_portal(binding, 'released')
        result = await self.broker.request({'version': 1, 'command': 'end',
            'binding': binding, 'reference': reference})
        if result.get('durable_reduction_accepted') is not True:
            raise AdminUnavailable('Administrator end delivery was not durably acknowledged.')
        self.tracked.discard(tuple(binding[field] for field in IDENTITY_FIELDS))
        return result

    async def flush_reductions(self):
        registry = self.channel.registry
        for event in registry.admin_end_events():
            binding = loads(event['binding_json'].encode('utf-8'), 8192)
            try:
                await self.end(binding, 'Durable Reach workflow authority reduction')
            except AdminUnavailable:
                continue
            registry.acknowledge_admin_end(event['scope'], event['binding_json'])

    async def reduction_loop(self):
        # Only reductions retry. Administrator execute/prepare calls never replay.
        while True:
            try:
                await self.flush_reductions()
            except (OSError, RuntimeError, ChannelDenied):
                pass
            await asyncio.sleep(1)

    async def renew(self, binding):
        if tuple(binding[field] for field in IDENTITY_FIELDS) in self.tracked:
            result = await self.broker.request({'version': 1, 'command': 'renew', 'binding': binding})
            for item in self.pending.values():
                if _same(item['binding'], binding):
                    item['expires_at'] = binding['expires_at']
            for item in self.portal_entries.values():
                if not item.get('closed') and _same(item['binding'], binding):
                    item['expires_at'] = binding['expires_at']
            return result

    async def run(self, name, arguments, owner, ctx):
        validate_admin_call(name, arguments)
        binding = self.binding(owner, arguments)
        self.prune()
        if name == 'reach_revoke_admin':
            self.pending = {key: item for key, item in self.pending.items() if not _same(item['binding'], binding)}
            self._close_portal(binding, 'revoked')
            return await self.broker.request({'version': 1, 'command': 'revoke', 'binding': binding,
                'reference': 'Owner requested return to approval for each operation'})
        if name == 'reach_admin_status':
            if arguments['job_id'] in self.portal_entries:
                return await self._portal_poll(self.portal_entries[arguments['job_id']], binding, owner)
            return await self.broker.request({'version': 1, 'command': 'poll', 'binding': binding,
                'job_id': arguments['job_id']})
        transport, reason, observed = approval_transport(ctx)
        state, responses = getattr(ctx, 'request_state', None), getattr(ctx, 'input_responses', None)
        stage = 'request' if state is None and responses is None else 'continuation'
        if transport == 'openai' and _form_schemas.get() is None:
            transport, reason = None, 'form_metadata_unavailable'
        use_portal = self.portal_enabled and owner_page_needed(ctx, transport)
        if use_portal and (state is not None or responses is not None):
            raise AdminUnavailable('Approval form not completed; no administrator job ran. '
                'A native continuation cannot approve an owner-page request.')
        if transport is None and not use_portal:
            self.diagnostics({'stage': stage, 'vm_id': binding['vm_id'], 'refusal': reason, **observed})
            raise AdminUnavailable('Administrator work requires native human approval; no administrator permission was granted. '
                'Reason ' + reason + ': ' + REFUSALS[reason] + '. Negotiated protocol: '
                + str(observed['protocol_version']) + '; elicitation: ' + json.dumps(observed['elicitation_keys'])
                + '; extensions: ' + json.dumps(observed['extension_keys']) + '. Approval form not completed; no administrator job ran.')
        if state is None and responses is None:
            if len(self.pending) + sum(item['state'] == 'awaiting_owner_approval'
                    for item in self.portal_entries.values()) >= MAX_PENDING:
                raise AdminUnavailable('Too many administrator requests are awaiting an owner decision.')
            script = arguments['script'].encode('utf-8')
            prepared = await self.broker.request({'version': 1, 'command': 'prepare', 'binding': binding,
                'script_base64': base64.b64encode(script).decode('ascii'),
                'arguments': arguments.get('arguments', []), 'timeout_seconds': arguments.get('timeout_seconds', 60)})
            for field, length in (('operation_id', 32), ('request_sha256', 64), ('approval_nonce', 32)):
                if not isinstance(prepared.get(field), str) or not re.fullmatch('[a-f0-9]{%d}' % length, prepared[field]):
                    raise ChannelDenied()
            self.tracked.add(tuple(binding[field] for field in IDENTITY_FIELDS))
            nonce = secrets.token_hex(16)
            item = {'binding': binding, 'operation_id': prepared['operation_id'],
                'request_sha256': prepared['request_sha256'], 'approval_nonce': prepared['approval_nonce'],
                'arguments_sha256': hashlib.sha256(encoded(arguments)).hexdigest(),
                'expires_at': binding['expires_at'], 'workflow_release_verified': prepared.get('workflow_release_verified') is True}
            if prepared.get('permission_mode') == 'workflow':
                if not item['workflow_release_verified']:
                    await self.broker.request({'version': 1, 'command': 'revoke', 'binding': binding,
                        'reference': 'Reach session release checking is not verified for this workflow'})
                    raise AdminUnavailable('Workflow administrator permission was cleared because Reach session release checking is not verified. Each operation requires its own native owner approval.')
                return await self.execute(item, arguments, owner, None)
            if prepared.get('permission_mode') not in ({'ask_each', 'workflow'} if use_portal else {'ask_each'}):
                raise ChannelDenied()
            if use_portal:
                self.diagnostics({'stage': stage, 'vm_id': binding['vm_id'], 'transport': 'owner_page',
                    'operation_id': item['operation_id'], **observed})
                return self._start_owner_page(item, arguments)
            item['transport'] = transport
            self.pending[nonce] = item
            self.diagnostics({'stage': stage, 'vm_id': binding['vm_id'], 'transport': transport,
                'operation_id': item['operation_id'], **observed})
            from mcp.types import InputRequiredResult
            scope = ('Choose one operation, or allow administrator operations for this Reach workflow until '
                'release, expiry, gateway replacement or your revocation. '
                'This does not grant permission to other workflows.\n') if item['workflow_release_verified'] else 'Approve this exact operation.\n'
            choices = ['once', 'workflow', 'deny'] if item['workflow_release_verified'] else ['once', 'deny']
            message = ('Nexus requests administrator permission on ' + binding['vm_id'] + '.\n' + scope
                + 'Timeout: ' + str(arguments.get('timeout_seconds', 60)) + ' seconds.\n'
                'Arguments: ' + json.dumps(arguments.get('arguments', [])) + '\nPowerShell:\n' + arguments['script'])
            return InputRequiredResult(result_type='input_required', request_state=json.dumps({'version': 1, 'nonce': nonce,
                'binding': binding, 'request_sha256': item['request_sha256']}, separators=(',', ':')),
                input_requests={'owner_admin': approval_form(transport, message, choices)})
        if not isinstance(state, str) or not isinstance(responses, dict):
            raise ChannelDenied()
        try:
            continuation = loads(state.encode('utf-8'), 8192)
        except (ValueError, UnicodeError):
            raise ChannelDenied() from None
        if type(continuation) is not dict or set(continuation) != {'version', 'nonce', 'binding', 'request_sha256'} or continuation['version'] != 1:
            raise ChannelDenied()
        # Remove before processing: decline, invalid answers, uncertainty and
        # concurrent replay all consume this continuation without another dispatch.
        item = self.pending.pop(continuation['nonce'], None)
        if (item is None or item['expires_at'] <= self.clock() or not _same(binding, item['binding'])
                or continuation['binding'] != item['binding']
                or continuation['request_sha256'] != item['request_sha256']
                or item['arguments_sha256'] != hashlib.sha256(encoded(arguments)).hexdigest()
                or set(responses) != {'owner_admin'}):
            raise ChannelDenied()
        raw_answer = responses['owner_admin']
        answer = _plain(raw_answer)
        action = answer.get('action') if isinstance(answer, dict) else getattr(answer, 'action', None)
        content = answer.get('content') if isinstance(answer, dict) else getattr(answer, 'content', None)
        choice = content.get('choice') if type(content) is dict else None
        record = {'stage': stage, 'vm_id': binding['vm_id'], 'transport': item.get('transport'),
            'operation_id': item['operation_id'],
            'action': action if type(action) is str and action in {'accept', 'decline', 'cancel'} else 'invalid',
            'answer_type': type(raw_answer).__name__, 'answer_keys': _names(answer),
            'answer_field_types': _key_types(answer), 'action_type': type(action).__name__,
            'content_type': type(content).__name__, 'content_keys': _names(content),
            'content_field_types': _key_types(content), 'choice_type': type(choice).__name__,
            'known_choice': choice if type(choice) is str and choice in {'once', 'workflow', 'deny'} else None}
        if action == 'cancel':
            # Dismissed, or the client never displayed the form: not an owner decision.
            self.diagnostics(record)
            return {'ok': True, 'state': 'cancelled', 'owner_response': 'cancel', 'administrator_permission_granted': False,
                'detail': 'The approval form was dismissed or not displayed by the client. Nothing ran. Ask the owner before requesting again.'}
        if action == 'decline':
            self.diagnostics(record)
            return {'ok': True, 'state': 'declined', 'owner_response': 'decline', 'administrator_permission_granted': False}
        if action == 'accept' and type(choice) is str and choice == 'deny':
            # Preserve an explicit negative choice even if the client supplied
            # unexpected fields. Malformed approval must never reprompt denial.
            self.diagnostics({**record, 'choice': 'deny'})
            return {'ok': True, 'state': 'declined', 'administrator_permission_granted': False}
        reason = ('unexpected_action' if action != 'accept' else
            'invalid_content_type' if type(content) is not dict else
            'missing_choice' if 'choice' not in content else
            'unexpected_content_fields' if set(content) != {'choice'} else
            'invalid_choice_type' if type(choice) is not str else
            'unknown_choice' if choice not in {'once', 'workflow', 'deny'} else None)
        if reason is not None:
            if self.portal_enabled and action == 'accept':
                # A malformed native answer is not consent. Its continuation
                # was consumed above; move the same prepared operation to an
                # independently authenticated browser decision without prepare
                # or execute, and never reinterpret a decline or cancel.
                self.diagnostics({**record, 'response_refusal': reason, 'fallback': 'owner_page'})
                return self._start_owner_page(item, arguments, excluded=(continuation['nonce'],))
            self.diagnostics({**record, 'response_refusal': reason})
            raise AdminUnavailable('Approval form not completed; no administrator job ran. '
                'The client did not return a valid explicit owner choice; no administrator permission was granted.')
        self.diagnostics({**record, 'choice': content['choice']})
        if content['choice'] == 'workflow' and not item['workflow_release_verified']:
            raise ChannelDenied()
        if content['choice'] == 'deny':
            return {'ok': True, 'state': 'declined', 'administrator_permission_granted': False}
        return await self.execute(item, arguments, owner, content['choice'])

    async def execute(self, item, arguments, owner, choice, *, approval_reference=None):
        current = self.binding(owner, arguments)
        if not _same(current, item['binding']) or item['expires_at'] <= self.clock():
            raise ChannelDenied()
        if approval_reference is not None and (choice not in ('once', 'workflow') or item.get('approved') is not True
                or approval_reference != 'Reach owner page:' + item.get('request_id', '')):
            raise ChannelDenied()
        return await self.broker.request({'version': 1, 'command': 'execute', 'binding': current,
            'operation_id': item['operation_id'], 'request_sha256': item['request_sha256'],
            'approval_nonce': item['approval_nonce'], 'choice': choice,
            'approval_reference': approval_reference or
                (('MCP native owner elicitation:' + item['approval_nonce']) if choice is not None else None)})


def admin_catalog():
    base = {'workflow_token': {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{43}$', 'writeOnly': True}}
    return [
        {'name': 'reach_run_admin', 'description': 'Request administrator PowerShell work on the selected VM through Nexus. Native owner elicitation approves one exact operation. Permission for an entire Reach workflow is offered only after Reach session release checking is verified for that workflow. A missing supported human approval interface refuses administrator work.',
         'inputSchema': {'type': 'object', 'properties': {**base, 'script': {'type': 'string', 'maxLength': 16384},
            'arguments': {'type': 'array', 'items': {'type': 'string'}, 'maxItems': 32, 'default': []},
            'timeout_seconds': {'type': 'integer', 'minimum': 1, 'maximum': 300, 'default': 60}},
            'required': ['workflow_token', 'script'], 'additionalProperties': False}},
        {'name': 'reach_revoke_admin', 'description': 'Revoke administrator permission for this exact Reach workflow, returning to human approval for each operation. Already dispatched bounded work may finish.',
         'inputSchema': {'type': 'object', 'properties': base, 'required': ['workflow_token'], 'additionalProperties': False}},
        {'name': 'reach_admin_status', 'description': 'Read the status of this workflow\'s Nexus administrator job. Never restarts an uncertain or completed administrator command.',
         'inputSchema': {'type': 'object', 'properties': {**base, 'job_id': {'type': 'string', 'pattern': '^[a-f0-9]{32}$'}},
            'required': ['workflow_token', 'job_id'], 'additionalProperties': False}},
    ]
