"""Approval transport negotiation: ChatGPT extended forms, standard MCP forms and refusal diagnostics."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import httpx

from fastmcp import FastMCP
from mcp.types import InputRequiredResult

from channel import ChannelDenied
from admin_frontend import (ReachAdminFrontend, AdminUnavailable, NegotiationLog, OPENAI_FORMS, approval_transport,
    form_metadata_scope, install_form_metadata)
from gateway import ReachProvider
from test_admin_frontend import Broker, Registry
from test_gateway import catalog

OPENAI_CAPS = {'elicitation': {'form': {}}, 'extensions': {OPENAI_FORMS: {'form': {}}}}
# Compatibility fixture only: live logs so far identify the extension's outer
# name, not its contents. Do not present this as a captured iOS wire request.
EMPTY_EXTENSION_CAPS = {'elicitation': {'form': {}, 'url': {}},
    'experimental': {}, 'extensions': {OPENAI_FORMS: {}, 'io.modelcontextprotocol/ui': {}}}
USER_VERIFICATION_ONLY_CAPS = {'elicitation': {'form': {}, 'url': {}},
    'extensions': {OPENAI_FORMS: {'userVerification': {}}, 'io.modelcontextprotocol/ui': {}}}


def context(state=None, action=None, choice=None, capabilities=None, version='2026-07-28', info=None):
    caps = OPENAI_CAPS if capabilities is None else capabilities
    responses = None if action is None else {'owner_admin': SimpleNamespace(action=action,
        content=None if choice is None else {'choice': choice})}
    params = None if info is None else SimpleNamespace(client_info=info)
    return SimpleNamespace(request_context=SimpleNamespace(protocol_version=version,
        session=SimpleNamespace(client_capabilities=caps, client_params=params)),
        request_state=state, input_responses=responses)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = 100
        self.records = []
        self.registry = Registry(lambda: self.now)
        self.channel = SimpleNamespace(registry=self.registry, epoch='e' * 32)
        self.broker = Broker()
        self.front = ReachAdminFrontend(self.channel, self.broker, clock=lambda: self.now, diagnostics=self.records.append)
        self.args = {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43, 'script': 'whoami /all'}

    async def asyncSetUp(self):
        # Stands in for restore_form_metadata, which the gateway installs per request.
        self.scope = form_metadata_scope()
        self.schemas = self.scope.__enter__()

    async def asyncTearDown(self):
        self.scope.__exit__(None, None, None)

    async def ask(self, **kwargs):
        result = await self.front.run('reach_run_admin', self.args, '42', context(**kwargs))
        self.assertIsInstance(result, InputRequiredResult)
        return result

    def test_transport_selection_follows_declared_capabilities(self):
        self.assertEqual('openai', approval_transport(context())[0])
        self.assertEqual('standard', approval_transport(context(capabilities={'elicitation': {'form': {}}}))[0])
        self.assertEqual('standard', approval_transport(context(capabilities={'elicitation': {}}))[0])
        # The extension alone is not enough: OpenAI requires both declarations.
        self.assertEqual('no_form_elicitation', approval_transport(context(capabilities={'extensions': OPENAI_CAPS['extensions']}))[1])
        self.assertEqual('standard', approval_transport(context(capabilities={'elicitation': {'form': {}},
            'extensions': {OPENAI_FORMS: {'url': {}}}}))[0])

    def test_empty_extension_never_implies_extended_form_support(self):
        transport, reason, observed = approval_transport(context(capabilities=EMPTY_EXTENSION_CAPS))
        self.assertEqual(('standard', None), (transport, reason))
        self.assertNotIn('compatibility', observed)
        self.assertEqual([], observed['openai_elicitation_keys'])
        for core, expected in (({}, 'standard'), ({'url': {}}, None)):
            with self.subTest(core=core):
                caps = {'elicitation': core, 'extensions': {OPENAI_FORMS: {}}}
                self.assertEqual(expected, approval_transport(context(capabilities=caps))[0])

    def test_only_positive_form_flag_is_bounded_wire_compatibility(self):
        for extension, compatibility in (({'form': True}, 'openai_boolean_form'),
                ({'form': True, 'url': {}}, 'openai_boolean_form')):
            with self.subTest(extension=extension):
                caps = {'elicitation': {'form': {}}, 'extensions': {OPENAI_FORMS: extension}}
                transport, reason, observed = approval_transport(context(capabilities=caps))
                self.assertEqual(('openai', None), (transport, reason))
                self.assertEqual(compatibility, observed['compatibility'])
                self.assertEqual({key: type(value).__name__ for key, value in extension.items()},
                    observed['openai_elicitation_key_types'])
                for core in ({}, {'url': {}}):
                    caps['elicitation'] = core
                    self.assertNotEqual('openai', approval_transport(context(capabilities=caps))[0])

    def test_user_verification_and_version_namespace_do_not_imply_extended_forms(self):
        for extension in ({}, {'version': 1}, {'version': 'fixture-version'}, {'userVerification': {}},
                {'userVerification': {}, 'version': 1}):
            with self.subTest(extension=extension):
                caps = {'elicitation': {'form': {}}, 'extensions': {OPENAI_FORMS: extension}}
                transport, reason, observed = approval_transport(context(capabilities=caps))
                self.assertEqual(('standard', None), (transport, reason))
                self.assertNotIn('compatibility', observed)
                self.assertNotIn('fixture-version', json.dumps(observed))

    def test_url_only_metadata_and_explicit_bad_form_do_not_select_openai(self):
        for extension in ({'url': {}, 'version': 1}, {'url': True, 'version': 1},
                {'form': False, 'version': 1}, {'form': None, 'version': 1},
                {'form': [], 'version': 1}, {'form': 'enabled', 'version': 1},
                {'form': 1}, {'form': 0}):
            with self.subTest(extension=extension):
                caps = {'elicitation': {'form': {}}, 'extensions': {OPENAI_FORMS: extension}}
                self.assertEqual('standard', approval_transport(context(capabilities=caps))[0])

    def test_non_form_extension_does_not_select_extended_forms(self):
        for extension in (None, False, True, [], 'form', {'url': {}},
                          {'form': None}, {'form': False}, {'form': []}, {'form': 'enabled'}):
            with self.subTest(extension=extension):
                caps = {'elicitation': {'form': {}}, 'extensions': {OPENAI_FORMS: extension}}
                self.assertEqual('standard', approval_transport(context(capabilities=caps))[0])

    async def test_malformed_core_form_and_protocol_refuse_before_prepare(self):
        for form in (None, False, True, [], 'enabled'):
            with self.subTest(form=form):
                caps = {'elicitation': {'form': form}, 'extensions': {OPENAI_FORMS: {}}}
                with self.assertRaisesRegex(AdminUnavailable, 'no_form_elicitation'):
                    await self.front.run('reach_run_admin', self.args, '42', context(capabilities=caps))
        for version in (None, [], {}, True):
            with self.subTest(version=version):
                with self.assertRaisesRegex(AdminUnavailable, 'handshake_protocol'):
                    await self.front.run('reach_run_admin', self.args, '42', context(version=version))
        self.assertFalse(self.broker.calls)

    def test_extension_diagnostics_report_shape_without_values(self):
        caps = {'elicitation': {'form': {}},
                'extensions': {OPENAI_FORMS: {'form': {'sensitive_setting': 'do-not-log-me'}}}}
        transport, _, observed = approval_transport(context(capabilities=caps))
        self.assertEqual('openai', transport)
        self.assertEqual('dict', observed['openai_elicitation_type'])
        self.assertEqual(['form'], observed['openai_elicitation_keys'])
        self.assertEqual('dict', observed['openai_form_type'])
        self.assertNotIn('do-not-log-me', json.dumps(observed))
        self.assertNotIn('sensitive_setting', json.dumps(observed))

    async def test_openai_form_has_empty_core_schema_and_real_schema_in_meta(self):
        request = (await self.ask()).input_requests['owner_admin']
        wire = request.model_dump(by_alias=True, exclude_none=True, mode='json')
        self.assertEqual({'type': 'object', 'properties': {}}, wire['params']['requestedSchema'])
        schema = wire['params']['_meta'][OPENAI_FORMS]['requestedSchema']
        self.assertEqual(['choice'], schema['required'])
        self.assertEqual(['once', 'workflow', 'deny'], [o['const'] for o in schema['properties']['choice']['oneOf']])
        self.assertIn('whoami /all', wire['params']['message'])
        self.assertFalse(self.broker.dispatched)

    async def test_standard_form_keeps_choice_in_core_schema_without_unsupported_keywords(self):
        request = (await self.ask(capabilities={'elicitation': {'form': {}}})).input_requests['owner_admin']
        wire = request.model_dump(by_alias=True, exclude_none=True, mode='json')
        self.assertNotIn('_meta', wire['params'])
        self.assertNotIn('additionalProperties', wire['params']['requestedSchema'])
        self.assertEqual(['once', 'workflow', 'deny'], wire['params']['requestedSchema']['properties']['choice']['enum'])

    async def test_each_refusal_branch_is_reported_and_prepares_nothing(self):
        cases = {'handshake_protocol': context(version='2025-11-25'),
                 'no_capabilities': context(capabilities=None) if False else SimpleNamespace(request_context=SimpleNamespace(
                     protocol_version='2026-07-28', session=SimpleNamespace(client_capabilities=None, client_params=None)),
                     request_state=None, input_responses=None),
                 'no_form_elicitation': context(capabilities={'elicitation': {'url': {}}}),
                 'no_request_context': SimpleNamespace(request_context=None, request_state=None, input_responses=None)}
        for reason, ctx in cases.items():
            with self.assertRaisesRegex(AdminUnavailable, 'native human approval.*Reason ' + reason):
                await self.front.run('reach_run_admin', self.args, '42', ctx)
        self.assertFalse(self.broker.calls)
        self.assertEqual(list(cases), [r['refusal'] for r in self.records])

    async def test_openai_form_without_metadata_middleware_is_refused_before_prepare(self):
        self.scope.__exit__(None, None, None)
        try:
            with self.assertRaisesRegex(AdminUnavailable, 'form_metadata_unavailable'):
                await self.front.run('reach_run_admin', self.args, '42', context())
            self.assertFalse(self.broker.calls)
            # Standard MCP forms carry their schema in the core field and need no middleware.
            result = await self.front.run('reach_run_admin', self.args, '42', context(capabilities={'elicitation': {'form': {}}}))
            self.assertIsInstance(result, InputRequiredResult)
        finally:
            self.scope = form_metadata_scope()
            self.schemas = self.scope.__enter__()

    async def test_unknown_future_protocol_is_refused_not_guessed(self):
        with self.assertRaisesRegex(AdminUnavailable, 'handshake_protocol.*2099-01-01'):
            await self.front.run('reach_run_admin', self.args, '42', context(version='2099-01-01'))
        self.assertFalse(self.broker.calls)

    async def test_decline_and_cancel_are_distinct_and_never_dispatch(self):
        state = (await self.ask()).request_state
        result = await self.front.run('reach_run_admin', self.args, '42', context(state, 'decline'))
        self.assertEqual(('declined', 'decline'), (result['state'], result['owner_response']))
        state = (await self.ask()).request_state
        result = await self.front.run('reach_run_admin', self.args, '42', context(state, 'cancel'))
        self.assertEqual(('cancelled', 'cancel'), (result['state'], result['owner_response']))
        self.assertFalse(result['administrator_permission_granted'])
        # A consumed cancel cannot be replayed as an accept.
        with self.assertRaises(ChannelDenied):
            await self.front.run('reach_run_admin', self.args, '42', context(state, 'accept', 'once'))
        self.assertFalse(self.broker.dispatched)
        self.assertEqual(['decline', 'cancel'], [r['action'] for r in self.records if 'action' in r])

    async def test_malformed_answers_never_dispatch(self):
        for action, content in (('accept', None), ('accept', {'choice': 'yes'}), ('accept', {'choice': 'once', 'x': 1}), ('approve', None)):
            state = (await self.ask()).request_state
            ctx = context(state, 'accept', 'once')
            ctx.input_responses['owner_admin'] = SimpleNamespace(action=action, content=content)
            with self.assertRaisesRegex(AdminUnavailable, 'Approval form not completed; no administrator job ran'):
                await self.front.run('reach_run_admin', self.args, '42', ctx)
        self.assertFalse(self.broker.dispatched)

    async def test_empty_accept_is_not_an_owner_choice(self):
        state = (await self.ask()).request_state
        ctx = context(state, 'accept')
        ctx.input_responses['owner_admin'] = {'action': 'accept', 'content': {}}
        with self.assertRaisesRegex(AdminUnavailable, 'Approval form not completed; no administrator job ran'):
            await self.front.run('reach_run_admin', self.args, '42', ctx)
        self.assertEqual('accept', self.records[-1]['action'])
        self.assertEqual('missing_choice', self.records[-1]['response_refusal'])
        self.assertEqual([], self.records[-1]['content_keys'])
        self.assertFalse(self.broker.dispatched)
        with self.assertRaises(ChannelDenied):
            await self.front.run('reach_run_admin', self.args, '42', context(state, 'accept', 'once'))

    async def test_response_shape_diagnostics_retain_accept_without_logging_values(self):
        bad_answers = [({'choice': ['once']}, 'invalid_choice_type'),
            ({'choice': {'const': 'once'}}, 'invalid_choice_type'),
            ({'choice': 'private-not-a-valid-option'}, 'unknown_choice'),
            ({'choice': 'once', 'userVerification': 'private-attestation'}, 'unexpected_content_fields')]
        for content, reason in bad_answers:
            with self.subTest(reason=reason):
                state = (await self.ask()).request_state
                ctx = context(state, 'accept')
                ctx.input_responses['owner_admin'] = {'action': 'accept', 'content': content}
                with self.assertRaisesRegex(AdminUnavailable, 'Approval form not completed; no administrator job ran'):
                    await self.front.run('reach_run_admin', self.args, '42', ctx)
                record = self.records[-1]
                self.assertEqual('accept', record['action'])
                self.assertEqual(reason, record['response_refusal'])
                self.assertEqual('dict', record['answer_type'])
                self.assertEqual('dict', record['content_type'])
                self.assertEqual(type(content['choice']).__name__, record['choice_type'])
                self.assertNotIn('private-not-a-valid-option', json.dumps(record))
                self.assertNotIn('private-attestation', json.dumps(record))
        self.assertFalse(self.broker.dispatched)

    async def test_openai_accept_once_dispatches_exactly_once(self):
        state = (await self.ask()).request_state
        result = await self.front.run('reach_run_admin', self.args, '42', context(state, 'accept', 'once'))
        self.assertEqual('running', result['state'])
        with self.assertRaises(ChannelDenied):
            await self.front.run('reach_run_admin', self.args, '42', context(state, 'accept', 'once'))
        self.assertEqual(1, len(self.broker.dispatched))

    async def test_dict_shaped_answers_are_accepted_identically(self):
        state = (await self.ask()).request_state
        ctx = context(state, 'accept', 'once')
        ctx.input_responses['owner_admin'] = {'action': 'accept', 'content': {'choice': 'once'}}
        self.assertEqual('running', (await self.front.run('reach_run_admin', self.args, '42', ctx))['state'])

    async def test_diagnostics_never_contain_token_script_or_arguments(self):
        self.args['arguments'] = ['secret-arg']
        state = (await self.ask(info={'name': 'chatgpt', 'version': '1'})).request_state
        await self.front.run('reach_run_admin', self.args, '42', context(state, 'decline'))
        text = json.dumps(self.records)
        for secret in ('t' * 43, 'whoami', 'secret-arg'):
            self.assertNotIn(secret, text)
        self.assertEqual({'name': 'chatgpt', 'version': '1'}, self.records[0]['client'])

    def test_negotiation_log_is_bounded_and_never_raises(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as root:
            log = NegotiationLog(os.path.join(root, 'a', 'n.jsonl'), limit=200)
            for _ in range(20):
                log({'stage': 'request', 'refusal': 'no_capabilities'})
            self.assertLessEqual(os.path.getsize(os.path.join(root, 'a', 'n.jsonl')), 400)
            self.assertTrue(os.path.exists(os.path.join(root, 'a', 'n.jsonl.1')))
        NegotiationLog(os.path.join('\0bad', 'x'))({'stage': 'request'})


class WireTests(unittest.IsolatedAsyncioTestCase):
    """Raw 2026-07-28 HTTP envelope as an extended-forms host sends it."""
    def setUp(self):
        self.records = []
        self.registry = Registry(lambda: 100)
        self.channel = SimpleNamespace(registry=self.registry, epoch='e' * 32)
        self.broker = Broker()
        self.front = ReachAdminFrontend(self.channel, self.broker, clock=lambda: 100, diagnostics=self.records.append)
        server = FastMCP('fixture', providers=[ReachProvider(self.channel, catalog(), admin=self.front)])
        install_form_metadata(server)
        install_form_metadata(server)
        self.assertEqual(1, server._mcp_server.middleware.count(install_form_metadata.__globals__['restore_form_metadata']))
        self.app = server.http_app(path='/mcp', stateless_http=True, json_response=True)
        self.args = {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43, 'script': 'whoami /all'}

    def envelope(self, caps, **extra):
        return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'reach_run_admin',
            'arguments': self.args, '_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientInfo': {'name': 'fixture-host', 'version': '1'},
            'io.modelcontextprotocol/clientCapabilities': caps}, **extra}}

    async def post(self, payload):
        headers = {'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call', 'Mcp-Name': payload['params']['name'],
                   'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json'}
        async with self.app.router.lifespan_context(self.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url='http://127.0.0.1') as client:
                response = await client.post('/mcp', json=payload, headers=headers)
        return response

    async def test_openai_round_trip_over_wire(self):
        with patch('gateway.subject', return_value='42'):
            first = await self.post(self.envelope(OPENAI_CAPS))
            self.assertEqual(200, first.status_code, first.text)
            result = first.json()['result']
            self.assertEqual('input_required', result['resultType'])
            params = result['inputRequests']['owner_admin']['params']
            self.assertEqual({'type': 'object', 'properties': {}}, params['requestedSchema'])
            self.assertIn('choice', params['_meta'][OPENAI_FORMS]['requestedSchema']['properties'])
            self.assertFalse(self.broker.dispatched)
            second = await self.post(self.envelope(OPENAI_CAPS, requestState=result['requestState'],
                inputResponses={'owner_admin': {'action': 'accept', 'content': {'choice': 'once'}}}))
            self.assertEqual(200, second.status_code, second.text)
            self.assertEqual('running', second.json()['result']['structuredContent']['state'])
        self.assertEqual(1, len(self.broker.dispatched))
        self.assertEqual('fixture-host', self.records[0]['client']['name'])

    async def test_namespace_only_standard_round_trip_still_requires_owner_accept(self):
        with patch('gateway.subject', return_value='42'):
            first = await self.post(self.envelope(EMPTY_EXTENSION_CAPS))
            self.assertEqual(200, first.status_code, first.text)
            result = first.json()['result']
            self.assertEqual('input_required', result['resultType'])
            params = result['inputRequests']['owner_admin']['params']
            self.assertIn('choice', params['requestedSchema']['properties'])
            self.assertNotIn('_meta', params)
            self.assertFalse(self.broker.dispatched)
            second = await self.post(self.envelope(EMPTY_EXTENSION_CAPS, requestState=result['requestState'],
                inputResponses={'owner_admin': {'action': 'accept', 'content': {'choice': 'once'}}}))
            self.assertEqual('running', second.json()['result']['structuredContent']['state'])
            replay = await self.post(self.envelope(EMPTY_EXTENSION_CAPS, requestState=result['requestState'],
                inputResponses={'owner_admin': {'action': 'accept', 'content': {'choice': 'once'}}}))
            self.assertTrue(replay.json()['result']['isError'])
        self.assertEqual(1, len(self.broker.dispatched))
        self.assertEqual('standard', self.records[0]['transport'])
        self.assertNotIn('compatibility', self.records[0])

    async def test_empty_extension_compatibility_decline_and_cancel_never_dispatch(self):
        with patch('gateway.subject', return_value='42'):
            for action, expected in (('decline', 'declined'), ('cancel', 'cancelled')):
                with self.subTest(action=action):
                    first = await self.post(self.envelope(EMPTY_EXTENSION_CAPS))
                    result = first.json()['result']
                    second = await self.post(self.envelope(EMPTY_EXTENSION_CAPS, requestState=result['requestState'],
                        inputResponses={'owner_admin': {'action': action, 'content': None}}))
                    self.assertEqual(expected, second.json()['result']['structuredContent']['state'])
        self.assertFalse(self.broker.dispatched)

    async def test_positive_true_flag_keeps_native_accept_deny_cancel_and_replay_fences(self):
        with patch('gateway.subject', return_value='42'):
            for extension in ({'form': {}}, {'form': True}):
                caps = {'elicitation': {'form': {}}, 'extensions': {OPENAI_FORMS: extension}}
                for action, content, expected in (('accept', {'choice': 'once'}, 'running'),
                        ('accept', {'choice': 'deny'}, 'declined'),
                        ('decline', None, 'declined'), ('cancel', None, 'cancelled')):
                    with self.subTest(extension=extension, action=action, content=content):
                        before = len(self.broker.dispatched)
                        first = await self.post(self.envelope(caps))
                        result = first.json()['result']
                        self.assertEqual('input_required', result['resultType'])
                        params = result['inputRequests']['owner_admin']['params']
                        self.assertEqual({'type': 'object', 'properties': {}}, params['requestedSchema'])
                        self.assertIn('choice', params['_meta'][OPENAI_FORMS]['requestedSchema']['properties'])
                        self.assertEqual(before, len(self.broker.dispatched))
                        second = await self.post(self.envelope(caps, requestState=result['requestState'],
                            inputResponses={'owner_admin': {'action': action, 'content': content}}))
                        self.assertEqual(expected, second.json()['result']['structuredContent']['state'])
                        self.assertEqual(before + int(expected == 'running'), len(self.broker.dispatched))
                        replay = await self.post(self.envelope(caps, requestState=result['requestState'],
                            inputResponses={'owner_admin': {'action': 'accept', 'content': {'choice': 'once'}}}))
                        self.assertTrue(replay.json()['result']['isError'])
        self.assertEqual(2, len(self.broker.dispatched))
        self.assertFalse(self.broker.grants)

    async def capability_call(self, capabilities, worker_result):
        self.native_calls = []
        async def native(name, arguments, vm_id, owner, workflow_token):
            self.registry.authorize_reservation(vm_id, owner, self.channel.epoch, workflow_token)
            self.native_calls.append((name, arguments, vm_id))
            return worker_result
        self.channel.request = native
        payload = self.envelope(capabilities)
        payload['params']['name'] = 'reach_get_capabilities'
        payload['params']['arguments'] = {'vm_id': 'vm-alpha', 'workflow_token': 't' * 43}
        with patch('gateway.subject', return_value='42'):
            response = await self.post(payload)
        self.assertEqual(200, response.status_code, response.text)
        return response.json()['result']

    async def test_capability_probe_observes_real_http_request_without_admin_prepare(self):
        worker_content = [{'type': 'text', 'text': 'worker capabilities retained'}]
        worker_structure = {'filesystem': {'enabled': True}, 'execution': {'enabled': True}}
        result = await self.capability_call(USER_VERIFICATION_ONLY_CAPS,
            {'content': worker_content, 'structuredContent': worker_structure, 'isError': False})
        self.assertFalse(result.get('isError', False))
        self.assertEqual(worker_content, result['content'][:-1])
        self.assertEqual(worker_structure['filesystem'], result['structuredContent']['filesystem'])
        self.assertEqual(worker_structure['execution'], result['structuredContent']['execution'])
        diagnostic = result['structuredContent']['gateway_admin_approval']
        self.assertEqual(diagnostic, json.loads(result['content'][-1]['text'])['gateway_admin_approval'])
        self.assertEqual('standard', diagnostic['selected_transport'])
        self.assertIsNone(diagnostic['refusal'])
        self.assertFalse(diagnostic['administrator_permission_granted'])
        self.assertEqual(['userVerification'], diagnostic['observed']['openai_elicitation_keys'])
        self.assertEqual('dict', diagnostic['observed']['openai_elicitation_type'])
        self.assertEqual('fixture-host', diagnostic['observed']['client']['name'])
        self.assertEqual([('reach_get_capabilities', {}, 'vm-alpha')], self.native_calls)
        self.assertFalse(self.broker.calls)
        self.assertFalse(self.front.pending)
        self.assertFalse(self.records)
        for secret in ('t' * 43, 'whoami', 'request_sha256', 'control_id', 'lease_id', 'approval_nonce'):
            self.assertNotIn(secret, json.dumps(diagnostic))

    async def test_capability_probe_preserves_worker_errors_without_adding_diagnostics(self):
        worker = {'content': [{'type': 'text', 'text': 'worker capability lookup failed'}],
            'structuredContent': {'worker_error': 'unavailable'}, 'isError': True}
        result = await self.capability_call(EMPTY_EXTENSION_CAPS, worker)
        self.assertTrue(result['isError'])
        self.assertEqual(worker['content'], result['content'])
        self.assertEqual(worker['structuredContent'], result['structuredContent'])
        self.assertFalse(self.broker.calls)

    async def test_capability_probe_reports_unavailable_forms_without_rejecting_capability_read(self):
        result = await self.capability_call({'elicitation': {'url': {}}},
            {'content': [{'type': 'text', 'text': 'worker still available'}], 'isError': False})
        diagnostic = result['structuredContent']['gateway_admin_approval']
        self.assertIsNone(diagnostic['selected_transport'])
        self.assertEqual('no_form_elicitation', diagnostic['refusal'])
        self.assertFalse(diagnostic['administrator_permission_granted'])
        self.assertEqual('worker still available', result['content'][0]['text'])
        self.assertFalse(self.broker.calls)

    async def test_empty_accept_over_real_http_refuses_with_specific_error_and_actual_action(self):
        with patch('gateway.subject', return_value='42'):
            first = await self.post(self.envelope(USER_VERIFICATION_ONLY_CAPS))
            pending = first.json()['result']
            self.assertEqual('input_required', pending['resultType'])
            self.assertIn('choice', pending['inputRequests']['owner_admin']['params']['requestedSchema']['properties'])
            second = await self.post(self.envelope(USER_VERIFICATION_ONLY_CAPS,
                requestState=pending['requestState'],
                inputResponses={'owner_admin': {'action': 'accept', 'content': {}}}))
            result = second.json()['result']
        self.assertTrue(result['isError'])
        self.assertIn('Approval form not completed; no administrator job ran', result['content'][0]['text'])
        self.assertEqual('ElicitResult', self.records[-1]['answer_type'])
        self.assertEqual('accept', self.records[-1]['action'])
        self.assertEqual('missing_choice', self.records[-1]['response_refusal'])
        self.assertFalse(self.broker.dispatched)

    async def test_extension_only_capability_over_wire_is_refused_with_reason(self):
        with patch('gateway.subject', return_value='42'):
            response = await self.post(self.envelope({'extensions': OPENAI_CAPS['extensions']}))
        result = response.json()['result']
        self.assertTrue(result['isError'])
        self.assertIn('no_form_elicitation', result['content'][0]['text'])
        self.assertFalse(self.broker.calls)


if __name__ == '__main__':
    unittest.main()
