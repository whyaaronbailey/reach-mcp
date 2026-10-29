"""Human approval, exact workflow fences and actual FastMCP MRTR fixtures."""
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import httpx

from fastmcp import FastMCP, Client
from fastmcp.client.elicitation import ElicitResult
from mcp.types import InputRequiredResult

from channel import ChannelDenied
from admin_frontend import ReachAdminFrontend, AdminUnavailable, validate_admin_call
from gateway import ReachProvider, RPCGuard
from test_gateway import catalog


def identity(binding):
    return tuple(binding[k] for k in ('subject','vm_id','control_id','lease_id','gateway_epoch'))


class Registry:
    def __init__(self, clock):
        self.clock = clock
        self.control_id = 'c' * 32
        self.valid = True
        self.expires_at = 500
        self.vm_id = 'vm-alpha'

    def authorize_reservation(self, vm_id, owner, epoch, token, ready=True):
        if (not self.valid or self.clock() >= self.expires_at or vm_id != self.vm_id
                or owner != '42' or epoch != 'e' * 32 or token != 't' * 43):
            raise ChannelDenied()
        return {'lease_id':'l'*32}, {'control_id':self.control_id,'gateway_epoch':epoch,'expires_at':self.expires_at}


class Broker:
    """An independent owner ledger fixture, not an always-approving transport."""
    def __init__(self):
        self.calls = []
        self.prepared = {}
        self.grants = set()
        self.dispatched = []
        self.counter = 0
        self.workflow_release_verified = True

    async def request(self, value):
        self.calls.append(value)
        binding = identity(value['binding'])
        command = value['command']
        if command == 'prepare':
            self.counter += 1
            op = '%032x' % self.counter
            nonce = hashlib.sha256(op.encode()).hexdigest()[:32]
            sha = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
            self.prepared[op] = (binding, nonce, sha)
            return {'ok':True,'operation_id':op,'request_sha256':sha,'approval_nonce':nonce,
                    'permission_mode':'workflow' if binding in self.grants else 'ask_each',
                    'workflow_release_verified':self.workflow_release_verified}
        if command == 'execute':
            op = value['operation_id']
            expected = self.prepared.pop(op)
            if expected != (binding, value['approval_nonce'], value['request_sha256']):
                raise ChannelDenied()
            choice = value['choice']
            if choice is None and binding not in self.grants:
                raise ChannelDenied()
            if choice == 'workflow':
                self.grants.add(binding)
            if choice not in {None, 'once', 'workflow'}:
                raise ChannelDenied()
            self.dispatched.append(value)
            return {'ok':True,'job_id':op,'state':'running'}
        if command in {'revoke','end'}:
            self.grants.discard(binding)
            return {'ok':True,'mode':'ask_each','durable_reduction_accepted':True}
        if command == 'renew':
            return {'ok':True,'expires_at':value['binding']['expires_at']}
        if command == 'poll':
            if value['job_id'] not in {v['operation_id'] for v in self.dispatched if identity(v['binding']) == binding}:
                raise ChannelDenied()
            return {'ok':True,'job_id':value['job_id'],'state':'completed'}
        raise AssertionError(command)


def context(state=None, answer=None, capabilities=None, version='2026-07-28'):
    caps = {'elicitation':{'form':{}}} if capabilities is None else capabilities
    responses = None if answer is None else {'owner_admin':SimpleNamespace(action='accept',content={'choice':answer})}
    return SimpleNamespace(request_context=SimpleNamespace(protocol_version=version,
        session=SimpleNamespace(client_capabilities=caps)), request_state=state, input_responses=responses)


class AdminFrontendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = 100
        self.registry = Registry(lambda:self.now)
        self.channel = SimpleNamespace(registry=self.registry,epoch='e'*32)
        self.broker = Broker()
        self.front = ReachAdminFrontend(self.channel,self.broker,clock=lambda:self.now)
        self.args = {'vm_id':'vm-alpha','workflow_token':'t'*43,'script':'Write-Output "fixture"'}

    async def ask(self):
        before = len(self.broker.dispatched)
        result = await self.front.run('reach_run_admin',self.args,'42',context())
        self.assertIsInstance(result,InputRequiredResult)
        self.assertEqual(before,len(self.broker.dispatched))
        return result.request_state

    async def answer(self, state, choice='once'):
        return await self.front.run('reach_run_admin',self.args,'42',context(state,choice))

    async def test_once_and_nonce_replay_are_fenced(self):
        state = await self.ask()
        self.assertEqual('running',(await self.answer(state))['state'])
        with self.assertRaises(ChannelDenied):
            await self.answer(state)
        self.assertEqual(1,len(self.broker.dispatched))
        self.assertFalse(self.broker.grants)

    async def test_deny_and_native_cancel_never_dispatch(self):
        state = await self.ask()
        self.assertEqual('declined',(await self.answer(state,'deny'))['state'])
        state = await self.ask()
        ctx = context(state,'once')
        ctx.input_responses['owner_admin'] = SimpleNamespace(action='cancel',content=None)
        self.assertEqual('cancelled',(await self.front.run('reach_run_admin',self.args,'42',ctx))['state'])
        self.assertFalse(self.broker.dispatched)

    async def test_unlimited_workflow_operations_then_revoke_requires_new_approval(self):
        await self.answer(await self.ask(),'workflow')
        for _ in range(4):
            result = await self.front.run('reach_run_admin',self.args,'42',context())
            self.assertEqual('running',result['state'])
        self.assertEqual(5,len(self.broker.dispatched))
        self.assertTrue(all(v['choice'] is None for v in self.broker.dispatched[1:]))
        await self.front.run('reach_revoke_admin',{k:v for k,v in self.args.items() if k!='script'},'42',context(capabilities={}))
        self.assertFalse(self.broker.grants)
        await self.ask()

    async def test_missing_capability_or_legacy_transport_cannot_prepare_admin(self):
        for ctx in (context(capabilities={}),context(capabilities={'elicitation':{'url':{}}}),context(version='2025-11-25')):
            with self.assertRaisesRegex(AdminUnavailable,'native human approval'):
                await self.front.run('reach_run_admin',self.args,'42',ctx)
        self.assertFalse(self.broker.calls)

    async def test_workflow_choice_requires_verified_session_end_lifecycle(self):
        self.broker.workflow_release_verified = False
        asked = await self.front.run('reach_run_admin',self.args,'42',context())
        schema = asked.input_requests['owner_admin'].params.requested_schema
        self.assertEqual(['once','deny'],schema['properties']['choice']['enum'])
        with self.assertRaises(ChannelDenied): await self.answer(asked.request_state,'workflow')
        self.assertFalse(self.broker.dispatched)
        self.assertEqual('running',(await self.answer(await self.ask(),'once'))['state'])
        self.broker.grants.add(identity(self.front.binding('42',self.args)))
        with self.assertRaisesRegex(AdminUnavailable,'session release checking'):
            await self.front.run('reach_run_admin',self.args,'42',context())
        self.assertFalse(self.broker.grants)

    async def test_changed_payload_wrong_hash_and_unknown_continuation_denied(self):
        state = await self.ask()
        self.args['script'] = 'Remove-Item fixture'
        with self.assertRaises(ChannelDenied): await self.answer(state)
        self.args['script'] = 'Write-Output "fixture"'
        state = json.loads(await self.ask())
        state['request_sha256'] = '0'*64
        with self.assertRaises(ChannelDenied): await self.answer(json.dumps(state))
        state['nonce'] = '0'*32
        with self.assertRaises(ChannelDenied): await self.answer(json.dumps(state))
        self.assertFalse(self.broker.dispatched)

    async def test_claim_replacement_release_and_expiry_deny_even_accepted_prompt(self):
        state = await self.ask()
        self.registry.control_id = 'd'*32
        with self.assertRaises(ChannelDenied): await self.answer(state)
        state = await self.ask()
        self.registry.valid = False
        with self.assertRaises(ChannelDenied): await self.answer(state)
        self.registry.valid = True
        state = await self.ask()
        self.now = 501
        with self.assertRaises(ChannelDenied): await self.answer(state)
        self.assertFalse(self.broker.dispatched)

    async def test_end_invalidates_pending_approval_and_workflow_grant(self):
        await self.answer(await self.ask(),'workflow')
        await self.front.end(self.front.binding('42',self.args))
        self.assertFalse(self.broker.grants)
        state = await self.ask()
        await self.front.end(self.front.binding('42',self.args))
        with self.assertRaises(ChannelDenied): await self.answer(state)

    async def test_end_delivers_reduction_and_renew_keeps_exact_binding(self):
        binding = self.front.binding('42',self.args)
        await self.front.renew(binding)
        await self.front.end(binding)
        self.assertEqual(['end'], [v['command'] for v in self.broker.calls])
        await self.answer(await self.ask(),'workflow')
        self.registry.expires_at = 700
        await self.front.renew(self.front.binding('42',self.args))
        self.assertEqual('renew',self.broker.calls[-1]['command'])
        self.assertEqual(700,self.broker.calls[-1]['binding']['expires_at'])
        self.assertEqual('c'*32,self.broker.calls[-1]['binding']['control_id'])

    async def test_status_cannot_follow_a_replacement_claim(self):
        job = await self.answer(await self.ask())
        args = {'vm_id':self.args['vm_id'],'workflow_token':'t'*43,'job_id':job['job_id']}
        self.assertEqual('completed',(await self.front.run('reach_admin_status',args,'42',context()))['state'])
        self.registry.control_id = 'd'*32
        with self.assertRaises(ChannelDenied):
            await self.front.run('reach_admin_status',args,'42',context())

    async def test_transport_uncertainty_consumes_continuation_without_automatic_retry(self):
        state = await self.ask()
        original = self.broker.request
        async def uncertain(value):
            result = await original(value)
            if value['command'] == 'execute':
                raise AdminUnavailable('Uncertain administrator delivery; no automatic retry was made.')
            return result
        self.broker.request = uncertain
        with self.assertRaises(AdminUnavailable): await self.answer(state)
        with self.assertRaises(ChannelDenied): await self.answer(state)
        self.assertEqual(1,len(self.broker.dispatched))

    async def test_http_guard_allows_mrtr_only_for_admin_and_never_public_approval_fields(self):
        async def accepted(scope,receive,send):
            await receive()
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'ok'})
        app = RPCGuard(accepted)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://reach.example.invalid') as client:
            params = {'name':'reach_run_admin','arguments':self.args,'inputResponses':{'owner_admin':{'action':'accept','content':{'choice':'once'}}},'requestState':'opaque-framework-sealed-state'}
            payload = {'jsonrpc':'2.0','id':1,'method':'tools/call','params':params}
            self.assertEqual(200,(await client.post('/mcp',json=payload)).status_code)
            params['arguments'] = {**self.args,'approved':True}
            self.assertEqual(403,(await client.post('/mcp',json=payload)).status_code)
            params.update({'name':'reach_run_command','arguments':{'vm_id':'vm-alpha','workflow_token':'t'*43,'command':'fixture'}})
            self.assertEqual(403,(await client.post('/mcp',json=payload)).status_code)

    async def test_real_fastmcp_client_round_trip_uses_native_elicitation(self):
        questions = []
        async def handler(message,response_type,params,ctx):
            questions.append(message)
            return ElicitResult(action='accept',content={'choice':'once'})
        server = FastMCP('fixture',providers=[ReachProvider(self.channel,catalog(),admin=self.front)])
        with patch('gateway.subject',return_value='42'):
            async with Client(server,elicitation_handler=handler) as client:
                result = await client.call_tool('reach_run_admin',self.args)
        self.assertFalse(result.is_error)
        self.assertEqual(1,len(questions))
        self.assertIn(self.args['script'],questions[0])
        self.assertEqual(1,len(self.broker.dispatched))

    async def test_real_client_without_elicitation_handler_fails_closed(self):
        server = FastMCP('fixture',providers=[ReachProvider(self.channel,catalog(),admin=self.front)])
        with patch('gateway.subject',return_value='42'):
            async with Client(server) as client:
                with self.assertRaisesRegex(Exception,'native human approval'):
                    await client.call_tool('reach_run_admin',self.args)
        self.assertFalse(self.broker.calls)

    def test_public_schema_never_accepts_approval_or_claim_labels(self):
        for key in ('approved','approval_reference','choice','control_id','session_id','generation'):
            with self.assertRaises(ChannelDenied):
                validate_admin_call('reach_run_admin',{**self.args,key:True})
        for wrong in ({**self.args,'timeout_seconds':True},{**self.args,'arguments':['\0']},
                      {**self.args,'vm_id':'vm-unknown'},{**self.args,'script':'x'*16385}):
            with self.assertRaises(ChannelDenied): validate_admin_call('reach_run_admin',wrong)


if __name__=='__main__':
    unittest.main()
