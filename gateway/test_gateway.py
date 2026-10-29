"""Public boundary fixture tests. These do not establish provider or desktop acceptance."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
import httpx
from fastmcp import FastMCP, Client
from fastmcp.server.auth.providers.github import GitHubTokenVerifier
from channel import EXPOSED_TOOLS, ChannelDenied
from gateway import (create_app, OwnerOnlyVerifier, PREFIX, PUBLIC, RESOURCE,
    READ_ONLY, ReachProvider, PUBLIC_TOOLS, DISCOVERY_TOOLS, RESERVATION_TOOLS, subject, validate_public_call)


def catalog():
    return {'tools':[{'name':name,'description':'Fixture '+name,
        'inputSchema':{'type':'object','properties':{}}} for name in sorted(EXPOSED_TOOLS)]}


class FakeChannel:
    def __init__(self):
        self.calls=[]
    def discovery(self, owner):
        return [{'vm_id':'vm-a','desktop_state':'ready','lease_active':False}] if owner=='42' else []
    async def request(self, name, args, vm_id, owner, workflow_token):
        self.calls.append((name,args,vm_id,owner,workflow_token))
        if vm_id not in {'vm-a','vm-b'} or owner!='42' or workflow_token!='f'*43:
            raise ChannelDenied()
        if name=='reach_screenshot':
            return {'content':[{'type':'image','data':'aGVsbG8=','mimeType':'image/png'}],'isError':False}
        return {'content':[{'type':'text','text':vm_id}],'isError':False}


def config():
    return {'oauth_config':{'public_url':PUBLIC,'client_id':'fixture-client-identifier',
        'client_secret':'fixture-github-secret-only','allowed_github_user_ids':[42],
        'owner_approval_oauth':{'client_id':'fixture-owner-portal-client-id',
            'client_secret':'fixture-owner-portal-client-secret'}},
        'oauth_key':'fixture-independent-signing-key-'*3}


class GatewayV2(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def fixture(self):
        self.channel=FakeChannel()
        self.app=create_app(config(),self.channel,catalog())
        async with self.app.router.lifespan_context(self.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                    base_url=PUBLIC,follow_redirects=False) as self.client:
                yield

    async def test_public_metadata_and_no_private_worker_routes(self):
        async with self.fixture():
            r=await self.client.get('/.well-known/oauth-authorization-server'+PREFIX)
            self.assertEqual(200,r.status_code)
            self.assertEqual(PUBLIC+PREFIX,r.json()['issuer'])
            r=await self.client.get('/.well-known/oauth-protected-resource'+RESOURCE)
            self.assertEqual(PUBLIC+RESOURCE,r.json()['resource'])
            for path in ('/worker/enroll','/worker/connect','/worker/next','/worker/result',
                    '/channel/next','/channel/result','/admin','/mcp',RESOURCE+'/'):
                self.assertEqual(404,(await self.client.post(path,json={})).status_code,path)
            self.assertFalse(self.channel.calls)

    async def test_missing_target_unknown_tool_and_duplicate_json_denied(self):
        async with self.fixture():
            self.assertEqual(401,(await self.client.post(RESOURCE,content=b'')).status_code)
            for name,args in [('reach_click',{}),('reach_screenshot',{'vm_id':''}),
                    ('reach_click',{'vm_id':'../vm-a'}),('owner_shell',{'vm_id':'vm-a'}),
                    ('reach_list_vms',{'vm_id':'vm-a'})]:
                payload={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}}
                self.assertEqual(403,(await self.client.post(RESOURCE,json=payload)).status_code)
            self.assertEqual(403,(await self.client.post(RESOURCE,content=b'{"method":"ping","method":"tools/list"}')).status_code)
            self.assertEqual(403,(await self.client.post(RESOURCE+'?token=fixture',content=b'')).status_code)
            self.assertFalse(self.channel.calls)

    async def test_owner_filter_and_missing_subject_fail_closed(self):
        verifier=OwnerOnlyVerifier(42,required_scopes=['read:user'],cache_ttl_seconds=0)
        for identity,allowed in [('42',True),('43',False)]:
            with patch.object(GitHubTokenVerifier,'verify_token',
                    new=AsyncMock(return_value=SimpleNamespace(subject=identity))):
                self.assertEqual(allowed,(await verifier.verify_token('fixture')) is not None)
        with patch('gateway.get_access_token',return_value=None):
            with self.assertRaises(ChannelDenied): subject()

    async def test_every_target_schema_requires_vm_and_preserves_pinned_catalog(self):
        before=catalog()
        server=FastMCP('fixture',providers=[ReachProvider(FakeChannel(),before)])
        async with Client(server) as client:
            values=await client.list_tools()
            self.assertEqual(PUBLIC_TOOLS,{t.name for t in values})
            for tool in values:
                self.assertEqual(tool.name in READ_ONLY|DISCOVERY_TOOLS,tool.annotations.read_only_hint)
                if tool.name!='reach_list_vms':
                    self.assertIn('vm_id',tool.input_schema['required'])
                if tool.name in EXPOSED_TOOLS:
                    self.assertIn('workflow_token',tool.input_schema['required'])
            self.assertTrue(all('vm_id' not in t['inputSchema']['properties'] for t in before['tools']))

    async def test_interleaved_targeting_strips_vm_from_native_arguments(self):
        channel=FakeChannel()
        server=FastMCP('fixture',providers=[ReachProvider(channel,catalog())])
        with patch('gateway.subject',return_value='42'):
            async with Client(server) as client:
                for vm in ('vm-a','vm-b','vm-a'):
                    await client.call_tool('reach_get_screen_info',{'vm_id':vm,'workflow_token':'f'*43})
                image=await client.call_tool('reach_screenshot',{'vm_id':'vm-b','workflow_token':'f'*43})
                self.assertEqual('image',image.content[0].type)
                self.assertEqual('aGVsbG8=',image.content[0].data)
        self.assertEqual(['vm-a','vm-b','vm-a','vm-b'],[x[2] for x in channel.calls])
        self.assertTrue(all(x[1]=={} and x[3]=='42' for x in channel.calls))

    async def test_discovery_no_desktop_dispatch_unknown_target_denied(self):
        channel=FakeChannel()
        provider=ReachProvider(channel,catalog())
        with patch('gateway.subject',return_value='42'):
            result=await (await provider._get_tool('reach_list_vms')).run({})
            self.assertEqual('vm-a',result.structured_content['vms'][0]['vm_id'])
            result=await (await provider._get_tool('reach_vm_status')).run({'vm_id':'vm-b'})
            self.assertTrue(result.is_error)
        self.assertFalse(channel.calls)

    async def test_capability_required_even_for_reads_and_cannot_be_agent_label(self):
        for name in EXPOSED_TOOLS:
            for arguments in ({'vm_id':'vm-a'}, {'vm_id':'vm-a','agent_id':'agent-a'},
                              {'vm_id':'vm-a','workflow_token':'invalid'}):
                with self.assertRaises(ChannelDenied):
                    validate_public_call(name,arguments)
        for name,arguments in (
                ('reach_claim_vm',{'vm_id':'vm-a','agent_id':'chosen'}),
                ('reach_claim_vm',{'vm_id':'vm-a','ttl_seconds':True}),
                ('reach_claim_vm',{'vm_id':'vm-a','ttl_seconds':601}),
                ('reach_release_vm',{'vm_id':'vm-a','workflow_token':'f'*43,'ttl_seconds':30})):
            with self.assertRaises(ChannelDenied):
                validate_public_call(name,arguments)
        validate_public_call('reach_claim_vm',{'vm_id':'vm-a'})
        validate_public_call('reach_renew_vm_claim',{'vm_id':'vm-a','workflow_token':'f'*43,'ttl_seconds':60})

    async def test_private_capability_not_in_error_or_native_arguments(self):
        channel=FakeChannel()
        provider=ReachProvider(channel,catalog())
        secret='s'*43
        with patch('gateway.subject',return_value='42'):
            result=await (await provider._get_tool('reach_read_file')).run(
                {'vm_id':'vm-a','workflow_token':secret,'path':'fixture'})
        self.assertTrue(result.is_error)
        self.assertNotIn(secret,str(result))
        self.assertEqual({'path':'fixture'},channel.calls[0][1])


if __name__=='__main__':
    unittest.main()
