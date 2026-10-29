"""One outbound worker channel; no guest listener and no automatic action replay."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import time

VM_UUID = 'e926e18d-0c2a-5aaa-b451-1c49f0da5744'
AGENT_SID = 'S-1-5-21-100-200-300-1001'
MAX_REQUEST = 262_144
MAX_RESULT = 8_388_608
MAX_LEASE = 7200
EXPOSED_TOOLS = frozenset({
    'reach_get_screen_info','reach_screenshot','reach_list_windows','reach_get_cursor_position',
    'reach_get_clipboard','reach_wait','reach_focus_window','reach_move_mouse','reach_click',
    'reach_drag','reach_scroll','reach_type_text','reach_press_keys','reach_set_clipboard',
    'reach_launch_application','reach_get_capabilities','reach_list_directory','reach_read_file',
    'reach_search_files','reach_write_file','reach_replace_text','reach_apply_patch',
    'reach_make_directory','reach_move_file','reach_remove_file','reach_run_command',
    'reach_read_process','reach_write_process','reach_cancel_process','reach_list_processes',
})


class ChannelDenied(RuntimeError):
    """Only this fixed public description crosses a boundary."""
    def __init__(self):
        super().__init__('Nexus Windows control is unavailable or not permitted.')


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ChannelDenied()
        value[key] = item
    return value


def _constant(_):
    raise ChannelDenied()


def loads(raw: bytes, maximum=MAX_REQUEST):
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise ChannelDenied()
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ChannelDenied() from None


def encoded(value, maximum=MAX_REQUEST):
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > maximum:
            raise ChannelDenied()
        return raw
    except (ValueError, TypeError, RecursionError):
        raise ChannelDenied() from None


def validate_request(method, params):
    if type(params) is not dict:
        raise ChannelDenied()
    if method == 'tools/list':
        if params:
            raise ChannelDenied()
    elif method == 'tools/call':
        if set(params) != {'name', 'arguments'} or params['name'] not in EXPOSED_TOOLS or type(params['arguments']) is not dict:
            raise ChannelDenied()
    else:
        raise ChannelDenied()
    encoded(params)


def validate_catalog(value):
    if type(value) is not dict or set(value) != {'tools'} or type(value['tools']) is not list:
        raise ChannelDenied()
    tools = value['tools']
    if len(tools) != len(EXPOSED_TOOLS) or {tool.get('name') for tool in tools if type(tool) is dict} != EXPOSED_TOOLS:
        raise ChannelDenied()
    for tool in tools:
        if type(tool) is not dict or type(tool.get('inputSchema')) is not dict:
            raise ChannelDenied()
    encoded(value, MAX_RESULT)
    return value


def catalog_digest(value):
    validate_catalog(value)
    normalized = {'tools':sorted(value['tools'],key=lambda tool:tool['name'])}
    return hashlib.sha256(json.dumps(normalized,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class Lease:
    channel_id: str
    token_sha256: str
    issued_at: int
    expires_at: int

    @classmethod
    def parse(cls, value, now=None):
        now = time.time() if now is None else now
        if type(value) is not dict or set(value) != {'version','channel_id','token_sha256','issued_at','expires_at','vm_uuid','agent_sid','approval_policy'}:
            raise ChannelDenied()
        if value['version'] != 1 or type(value['version']) is not int or value['vm_uuid'] != VM_UUID or value['agent_sid'] != AGENT_SID or value['approval_policy'] != 'client':
            raise ChannelDenied()
        if not isinstance(value['channel_id'], str) or not re.fullmatch('[0-9a-f]{32}', value['channel_id']):
            raise ChannelDenied()
        if not isinstance(value['token_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['token_sha256']):
            raise ChannelDenied()
        issued, expires = value['issued_at'], value['expires_at']
        if type(issued) is not int or type(expires) is not int or not issued <= now + 30 or not 0 < expires-issued <= MAX_LEASE or not now < expires:
            raise ChannelDenied()
        return cls(value['channel_id'], value['token_sha256'], issued, expires)

    def authenticate(self, authorization):
        if not isinstance(authorization, str) or not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43,128}', authorization):
            return False
        digest = hashlib.sha256(authorization[7:].encode('ascii')).hexdigest()
        return time.time() < self.expires_at and hmac.compare_digest(digest, self.token_sha256)


class LeaseFile:
    def __init__(self, path):
        self.path = Path(path)

    def current(self):
        try:
            return Lease.parse(loads(self.path.read_bytes(), 4096))
        except (OSError, ChannelDenied):
            raise ChannelDenied() from None


@dataclass
class Pending:
    identity: str
    lease: Lease
    method: str
    deadline: int
    future: asyncio.Future
    delivered: bool = False


class Channel:
    def __init__(self, leases, clock=time.time, timeout=90):
        self.leases = leases
        self.clock = clock
        self.timeout = timeout
        self.queue = asyncio.Queue(maxsize=1)
        self.pending = None
        self.lock = asyncio.Lock()
        self.last_poll = 0

    def authenticate(self, authorization):
        lease = self.leases.current()
        if not lease.authenticate(authorization):
            raise ChannelDenied()
        return lease

    async def request(self, method, params):
        validate_request(method, params)
        if self.lock.locked():
            raise ChannelDenied()
        async with self.lock:
            lease = self.leases.current()
            if self.clock()-self.last_poll > 30:
                raise ChannelDenied()
            deadline = min(int(self.clock()+self.timeout), lease.expires_at-1)
            if deadline <= self.clock():
                raise ChannelDenied()
            pending = Pending(secrets.token_hex(16), lease, method, deadline, asyncio.get_running_loop().create_future())
            self.pending = pending
            packet = {'version':1,'channel_id':lease.channel_id,'job_id':pending.identity,'deadline':deadline,'method':method,'params':params}
            self.queue.put_nowait(packet)
            try:
                result = await asyncio.wait_for(pending.future, max(.01, deadline-self.clock()))
                if self.leases.current() != lease:
                    raise ChannelDenied()
                return validate_catalog(result) if method == 'tools/list' else result
            except (asyncio.TimeoutError, asyncio.CancelledError):
                raise ChannelDenied() from None
            finally:
                self.pending = None
                # Undelivered work is discarded; delivered actions are never replayed.
                while not self.queue.empty():
                    self.queue.get_nowait()

    async def next(self, lease, wait=20):
        if self.leases.current() != lease:
            raise ChannelDenied()
        self.last_poll = self.clock()
        try:
            packet = await asyncio.wait_for(self.queue.get(), wait)
        except asyncio.TimeoutError:
            return None
        pending = self.pending
        if (pending is None or pending.identity != packet['job_id'] or pending.delivered
                or self.leases.current() != lease or pending.lease != lease or self.clock() >= pending.deadline):
            raise ChannelDenied()
        pending.delivered = True
        return packet

    def submit(self, lease, value):
        if type(value) is not dict or set(value) != {'version','channel_id','job_id','result','failed'}:
            raise ChannelDenied()
        pending = self.pending
        if (pending is None or self.leases.current() != lease or pending.lease != lease
                or not pending.delivered or pending.future.done() or self.clock() >= pending.deadline
                or value['version'] != 1 or type(value['version']) is not int
                or value['channel_id'] != lease.channel_id or value['job_id'] != pending.identity
                or type(value['failed']) is not bool):
            raise ChannelDenied()
        encoded(value, MAX_RESULT)
        if value['failed']:
            if value['result'] is not None:
                raise ChannelDenied()
            pending.future.set_exception(ChannelDenied())
        else:
            if type(value['result']) is not dict:
                raise ChannelDenied()
            pending.future.set_result(value['result'])
