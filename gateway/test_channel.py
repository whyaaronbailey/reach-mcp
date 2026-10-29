import asyncio
import hashlib
import json
import time
import unittest

from legacy_channel import AGENT_SID, VM_UUID, Channel, ChannelDenied, EXPOSED_TOOLS, Lease, encoded, loads, validate_catalog, validate_request
from legacy_private_api import PrivateAPI
from public_limits import PublicBodyLimit

TOKEN = 'fixture-capability-'+'x'*48


def lease_value():
    now = int(time.time())
    return {'version':1,'channel_id':'a'*32,'token_sha256':hashlib.sha256(TOKEN.encode()).hexdigest(),
        'issued_at':now,'expires_at':now+120,'vm_uuid':VM_UUID,'agent_sid':AGENT_SID,'approval_policy':'client'}


class Store:
    def __init__(self):
        self.lease = Lease.parse(lease_value())
    def current(self):
        return self.lease


def catalog():
    return {'tools':[{'name':name,'inputSchema':{'type':'object','properties':{}}} for name in sorted(EXPOSED_TOOLS)]}


class PureBoundary(unittest.TestCase):
    def test_exact_lease_identity_and_lifetime(self):
        original = lease_value()
        for key,value in [('vm_uuid','other'),('agent_sid','other'),('approval_policy','local'),('expires_at',original['issued_at']+7201),('version',True)]:
            with self.subTest(key=key),self.assertRaises(ChannelDenied):
                Lease.parse({**original,key:value})

    def test_expired_or_future_lease(self):
        value = lease_value()
        with self.assertRaises(ChannelDenied):Lease.parse(value,now=value['expires_at'])
        with self.assertRaises(ChannelDenied):Lease.parse(value,now=value['issued_at']-31)

    def test_auth_exact_and_no_query_credentials(self):
        lease = Lease.parse(lease_value())
        self.assertTrue(lease.authenticate('Bearer '+TOKEN))
        for header in ('bearer '+TOKEN,'Bearer '+TOKEN+' ','Bearer wrong','',None):
            self.assertFalse(lease.authenticate(header))

    def test_duplicate_or_nonfinite_json(self):
        for raw in (b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}',b'\xff'):
            with self.subTest(raw=raw),self.assertRaises(ChannelDenied):loads(raw)

    def test_request_size_and_fixed_methods(self):
        validate_request('tools/call',{'name':'reach_type_text','arguments':{'text':'line1\nline2'}})
        for method,params in [('resources/read',{}),('tools/list',{'cursor':'x'}),('tools/call',{'name':'owner_shell','arguments':{}}),('tools/call',{'name':'reach_click','arguments':{},'url':'http://other'})]:
            with self.subTest(method=method),self.assertRaises(ChannelDenied):validate_request(method,params)
        with self.assertRaises(ChannelDenied):encoded({'x':'x'*262144})

    def test_exact_thirty_catalog(self):
        self.assertEqual(30,len(validate_catalog(catalog())['tools']))
        bad = catalog();bad['tools'].append({'name':'new_upstream_tool','inputSchema':{}})
        with self.assertRaises(ChannelDenied):validate_catalog(bad)



class ChannelBoundary(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = Store();self.channel = Channel(self.store);self.channel.last_poll=time.time()

    async def submit_for(self,task,result):
        packet = await self.channel.next(self.store.current(),wait=1)
        self.channel.submit(self.store.current(),{'version':1,'channel_id':packet['channel_id'],'job_id':packet['job_id'],'result':result,'failed':False})
        return packet,await task

    async def test_authenticated_roundtrip(self):
        task=asyncio.create_task(self.channel.request('tools/list',{}))
        packet,result=await self.submit_for(task,catalog())
        self.assertEqual(packet['method'],'tools/list');self.assertEqual(30,len(result['tools']))

    async def test_wrong_job_and_unsolicited_results(self):
        with self.assertRaises(ChannelDenied):self.channel.submit(self.store.current(),{'version':1,'channel_id':'a'*32,'job_id':'b'*32,'result':{},'failed':False})
        task=asyncio.create_task(self.channel.request('tools/list',{}));packet=await self.channel.next(self.store.current(),wait=1)
        with self.assertRaises(ChannelDenied):self.channel.submit(self.store.current(),{'version':1,'channel_id':'a'*32,'job_id':'b'*32,'result':catalog(),'failed':False})
        task.cancel()
        with self.assertRaises(ChannelDenied):await task

    async def test_no_automatic_replay_after_cancel(self):
        task=asyncio.create_task(self.channel.request('tools/call',{'name':'reach_click','arguments':{'x':1,'y':1}}))
        packet=await self.channel.next(self.store.current(),wait=1)
        self.assertTrue(self.channel.pending.delivered)
        task.cancel()
        with self.assertRaises(ChannelDenied):await task
        self.assertIsNone(await self.channel.next(self.store.current(),wait=.01))
        with self.assertRaises(ChannelDenied):self.channel.submit(self.store.current(),{'version':1,'channel_id':'a'*32,'job_id':packet['job_id'],'result':{},'failed':False})

    async def test_busy_and_worker_offline_fail_closed(self):
        self.channel.last_poll=0
        with self.assertRaises(ChannelDenied):await self.channel.request('tools/list',{})
        self.channel.last_poll=time.time()
        task=asyncio.create_task(self.channel.request('tools/list',{}));await self.channel.next(self.store.current(),wait=1)
        with self.assertRaises(ChannelDenied):await self.channel.request('tools/list',{})
        task.cancel()
        with self.assertRaises(ChannelDenied):await task

    async def test_lease_rotation_rejects_old_reply(self):
        task=asyncio.create_task(self.channel.request('tools/list',{}));packet=await self.channel.next(self.store.current(),wait=1)
        old=self.store.current();self.store.lease=Lease.parse({**lease_value(),'channel_id':'b'*32})
        with self.assertRaises(ChannelDenied):self.channel.submit(old,{'version':1,'channel_id':packet['channel_id'],'job_id':packet['job_id'],'result':catalog(),'failed':False})
        task.cancel()
        with self.assertRaises(ChannelDenied):await task

    async def test_private_authority_and_no_query_or_duplicate_auth(self):
        app=PrivateAPI(self.channel)
        async def receive():return {'type':'http.request','body':b''}
        base={'type':'http','method':'GET','path':'/channel/next','raw_path':b'/channel/next','query_string':b'',
            'headers':[(b'host',b'192.0.2.1:19444'),(b'authorization',('Bearer '+TOKEN).encode())]}
        for patch in ({'query_string':b'token=anything'},{'raw_path':b'/channel/%6eext'},
                {'headers':[(b'host',b'reach.example.invalid'),(b'authorization',('Bearer '+TOKEN).encode())]},
                {'headers':base['headers']+[(b'authorization',('Bearer '+TOKEN).encode())]}):
            messages=[]
            async def send(message):messages.append(message)
            await app({**base,**patch},receive,send)
            self.assertEqual(403,messages[0]['status'])


class PublicBodyBoundary(unittest.IsolatedAsyncioTestCase):
    async def test_oversized_register_and_token_rejected_before_framework(self):
        for path in ('/auth/callback/reach/nexus/register','/auth/callback/reach/nexus/token'):
            with self.subTest(path=path):
                called=[];messages=[]
                async def inner(scope,receive,send):called.append(True)
                async def receive():return {'type':'http.request','body':b'x'*262145,'more_body':False}
                async def send(message):messages.append(message)
                await PublicBodyLimit(inner)({'type':'http','method':'POST','path':path,'headers':[]},receive,send)
                self.assertEqual(413,messages[0]['status']);self.assertFalse(called)

    async def test_declared_length_rejected_without_reading(self):
        called=[];messages=[]
        async def inner(scope,receive,send):called.append('inner')
        async def receive():called.append('read');return {'type':'http.request','body':b''}
        async def send(message):messages.append(message)
        await PublicBodyLimit(inner)({'type':'http','headers':[(b'content-length',b'999999999')]},receive,send)
        self.assertEqual(413,messages[0]['status']);self.assertFalse(called)

    async def test_small_form_and_lifespan_preserved(self):
        observed=[]
        async def inner(scope,receive,send):
            observed.append(scope['type'])
            if scope['type']=='http':observed.append((await receive())['body'])
        async def receive():return {'type':'http.request','body':b'grant_type=fixture','more_body':False}
        async def send(message):pass
        app=PublicBodyLimit(inner)
        await app({'type':'lifespan'},receive,send)
        await app({'type':'http','headers':[]},receive,send)
        self.assertEqual(['lifespan','http',b'grant_type=fixture'],observed)

    async def test_slow_body_bounded(self):
        called=[];messages=[]
        async def inner(scope,receive,send):called.append(True)
        async def receive():await asyncio.sleep(1)
        async def send(message):messages.append(message)
        await PublicBodyLimit(inner,seconds=.01)({'type':'http','headers':[]},receive,send)
        self.assertEqual(408,messages[0]['status']);self.assertFalse(called)


if __name__=='__main__':
    unittest.main()
