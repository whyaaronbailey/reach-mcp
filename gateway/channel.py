"""Pinned tool validation and isolated outbound worker channels; no action replay."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import re
import secrets

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
        super().__init__('Requested VM control is unavailable or not permitted.')


class WorkflowBusy(ChannelDenied):
    """Safe status for an authenticated workflow, without holder identity or secrets."""
    def __init__(self):
        RuntimeError.__init__(self,'VM workflow is busy or preparing; check reach_vm_status before retrying.')


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
    if type(value) is not dict or set(value) not in ({'tools'},{'tools','ttlMs','cacheScope','resultType'}):
        raise ChannelDenied()
    # The pinned native MCP catalog includes these exact non-persistent metadata fields.
    # Tools-only fixtures remain compatible; partial or changed metadata is refused.
    if set(value) != {'tools'} and (type(value['ttlMs']) is not int or value['ttlMs'] != 0
            or value['cacheScope'] != 'private' or value['resultType'] != 'complete'):
        raise ChannelDenied()
    if type(value['tools']) is not list:
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


@dataclass
class RoutedPending:
    packet: dict
    subject: str
    future: asyncio.Future
    delivered: bool = False


class VMChannel:
    def __init__(self):
        self.queue = asyncio.Queue(maxsize=1)
        self.lock = asyncio.Lock()
        self.pending = None
        self.polling = False


class Channel:
    """Per-VM dispatch. Credentials enroll transport; only an owner lease permits work."""
    def __init__(self, registry, timeout=90):
        self.registry = registry
        self.clock = registry.clock
        self.timeout = min(90, max(1, timeout))
        self.epoch = registry.start_gateway()
        self.channels = {}

    def state(self, vm_id):
        # An arbitrary caller cannot allocate state for unknown or unauthorized VMs.
        self.registry.get(vm_id)
        return self.channels.setdefault(vm_id, VMChannel())

    def discovery(self, subject):
        self.registry.assert_epoch(self.epoch)
        return self.registry.list_vms(subject)

    async def request(self, name, args, vm_id, subject, workflow_token):
        validate_request('tools/call', {'name':name,'arguments':args})
        lease, control = self.registry.authorize_reservation(vm_id, subject, self.epoch, workflow_token)
        state = self.state(vm_id)
        if state.lock.locked():
            raise WorkflowBusy()
        async with state.lock:
            lease, control = self.registry.authorize_reservation(vm_id, subject, self.epoch, workflow_token)
            vm = self.registry.get(vm_id)
            deadline = min(int(self.clock()+self.timeout), lease['expires_at'], control['expires_at'])
            if deadline <= self.clock():
                raise ChannelDenied()
            packet = {key:lease[key] for key in ('vm_id','instance_id','session_id','connection_id','gateway_epoch','lease_id')}
            packet.update({'version':2,'machine_uuid':vm['machine_uuid'],'account_sid':vm['account_sid'],
                'job_id':secrets.token_hex(16),'deadline':deadline,'lease_expires_at':lease['expires_at'],
                'control_id':control['control_id'],'control_expires_at':control['expires_at'],
                'approval_policy':'client','method':'tools/call','params':{'name':name,'arguments':args}})
            pending = RoutedPending(packet,subject,asyncio.get_running_loop().create_future())
            state.pending = pending
            recorded = False
            completed = False
            try:
                self.registry.create_job(packet,name)
                recorded = True
                state.queue.put_nowait(packet)
                while True:
                    self.registry.authorize_control(vm_id,subject,self.epoch,packet['control_id'])
                    remaining = deadline-self.clock()
                    if remaining <= 0:
                        raise ChannelDenied()
                    done,_ = await asyncio.wait([pending.future],timeout=min(.2,remaining))
                    if done:
                        result = pending.future.result()
                        self.registry.authorize_control(vm_id,subject,self.epoch,packet['control_id'])
                        completed = True
                        return result
            except asyncio.CancelledError:
                raise ChannelDenied() from None
            finally:
                if not pending.future.done():
                    pending.future.cancel()
                # Never retain payloads or requeue an action with uncertain outcome.
                state.pending = None
                while not state.queue.empty():
                    state.queue.get_nowait()
                if not completed:
                    self.registry.abandon_control(vm_id,packet['control_id'])
                # Clear executable state even if durable audit storage has failed.
                if recorded:
                    self.registry.finish_job(packet['job_id'],'outcome_uncertain' if pending.delivered else 'discarded')

    def worker_enroll(self, authorization, payload):
        self.registry.assert_epoch(self.epoch)
        return self.registry.enroll(authorization,payload)

    def worker_connect(self, authorization, payload):
        return self.registry.connect(authorization,payload,self.epoch)

    async def worker_next(self, authorization, payload, wait=20):
        self.registry.assert_epoch(self.epoch)
        connection = self.registry.connection(authorization,payload,heartbeat=True)
        state = self.state(connection['vm_id'])
        if state.polling:
            raise ChannelDenied()
        state.polling = True
        binding = {key:payload[key] for key in ('version','vm_id','instance_id','session_id','connection_id','gateway_epoch','control_id')}
        end = asyncio.get_running_loop().time() + min(20,max(0,wait))
        try:
            while True:
                self.registry.assert_epoch(self.epoch)
                self.registry.connection(authorization,binding)
                remaining = end-asyncio.get_running_loop().time()
                if remaining <= 0:
                    return None
                try:
                    packet = await asyncio.wait_for(state.queue.get(),min(.2,remaining))
                except asyncio.TimeoutError:
                    continue
                pending = state.pending
                if not pending or pending.packet is not packet or pending.delivered:
                    raise ChannelDenied()
                self.registry.authorize_control(packet['vm_id'],pending.subject,self.epoch,packet['control_id'])
                if self.clock() >= packet['deadline']:
                    raise ChannelDenied()
                for key in binding:
                    if packet.get(key) != binding[key]:
                        raise ChannelDenied()
                # Durable before bytes leave the gateway. A disconnect is uncertain, never retried.
                self.registry.deliver_job(packet)
                pending.delivered = True
                return packet
        finally:
            state.polling = False

    def worker_result(self, authorization, payload):
        from registry import CONNECTION_KEYS, exact
        exact(payload, CONNECTION_KEYS | {'lease_id','job_id','failed','result'})
        binding = {key:payload[key] for key in CONNECTION_KEYS}
        self.registry.assert_epoch(self.epoch)
        self.registry.connection(authorization,binding)
        state = self.state(payload['vm_id'])
        pending = state.pending
        if not pending or not pending.delivered or pending.future.done():
            raise ChannelDenied()
        packet = pending.packet
        for key in CONNECTION_KEYS | {'lease_id','job_id'}:
            if packet.get(key) != payload[key]:
                raise ChannelDenied()
        self.registry.authorize_control(payload['vm_id'],pending.subject,self.epoch,packet['control_id'])
        if self.clock() >= packet['deadline'] or type(payload['failed']) is not bool:
            raise ChannelDenied()
        encoded(payload,MAX_RESULT)
        if payload['failed']:
            if payload['result'] is not None:
                raise ChannelDenied()
            self.registry.finish_job(packet['job_id'],'failed')
            pending.future.set_exception(ChannelDenied())
        else:
            if type(payload['result']) is not dict:
                raise ChannelDenied()
            self.registry.finish_job(packet['job_id'],'completed')
            pending.future.set_result(payload['result'])
        return {'accepted':True}

    def worker_heartbeat(self, authorization, payload):
        self.registry.assert_epoch(self.epoch)
        connection = self.registry.connection(authorization,payload,heartbeat=True)
        return {'version':2,'vm_id':connection['vm_id'],'desktop_state':connection['desktop_state'],
                'lease':self.registry.lease_public(connection['vm_id']),
                'control':self.registry.control_public(connection['vm_id'])}

    def worker_revoke(self, authorization, payload):
        self.registry.assert_epoch(self.epoch)
        return self.registry.self_revoke(authorization,payload)
