"""Real TLS sockets with three SIMULATED workers; never controls a desktop.

Uses the production native Transport/ReplayGuard and private API, an ephemeral
loopback listener/certificate, and a disposable registry. This is transport
integration evidence, not Windows installer or desktop acceptance.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import uvicorn

from channel import Channel, ChannelDenied
from native_worker import Transport, ReplayGuard
from private_api import PrivateAPI
from registry import Registry, CONNECTION_KEYS


class RealTLSTransport(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.db_path=self.root/'registry.sqlite3'
        self.registry=Registry(self.db_path)
        self.addCleanup(self.cleanup_fixture)
        self.key_path=self.root/'server.key'
        self.cert_path=self.root/'gateway-ca.crt'
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Reach disposable test CA')])
        now=datetime.now(timezone.utc)
        certificate=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            .sign(key,hashes.SHA256()))
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0))
            self.port=listener.getsockname()[1]
        self.host=f'127.0.0.1:{self.port}'
        self.config={'gateway':'https://'+self.host,'ca_sha256':hashlib.sha256(self.cert_path.read_bytes()).hexdigest()}
        self.holder={}
        self.ready=threading.Event()
        def serve():
            async def run():
                registry=Registry(self.db_path)
                channel=Channel(registry)
                app=PrivateAPI(channel,[self.host])
                server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=self.port,
                    ssl_certfile=str(self.cert_path),ssl_keyfile=str(self.key_path),
                    access_log=False,log_config=None,log_level='critical',lifespan='off'))
                self.holder.update(loop=asyncio.get_running_loop(),server=server,registry=registry,channel=channel,app=app)
                self.ready.set()
                try:
                    await server.serve()
                finally:
                    registry.close()
            try:
                asyncio.run(run())
            except BaseException as error:
                self.holder['error']=error
                self.ready.set()
        self.thread=threading.Thread(target=serve,name='reach-disposable-tls-test',daemon=True)
        self.thread.start()
        self.assertTrue(self.ready.wait(5))
        deadline=time.monotonic()+5
        while not self.holder.get('error') and not self.holder['server'].started and time.monotonic()<deadline:
            time.sleep(.01)
        if self.holder.get('error'):
            raise self.holder['error']
        self.assertTrue(self.holder['server'].started)
        self.workers={}
        for number in (1,2,3):
            vm_id='vm-tls-fixture-'+str(number)
            identity={'version':2,'vm_id':vm_id,'machine_uuid':f'00000000-0000-0000-0001-{number:012x}',
                'account_sid':f'S-1-5-21-101-202-303-{number+1000}'}
            grant=self.registry.grant(vm_id,'TLS fixture '+str(number),identity['machine_uuid'],identity['account_sid'],['42'])
            enrollment=Transport(self.config,grant['enrollment_token'],self.root)
            credential=enrollment.request('/worker/enroll',identity)
            transport=Transport(self.config,credential['worker_token'],self.root)
            hello={**identity,'instance_id':f'{number:032x}','session_id':'testboot:testlogon','desktop_state':'ready','control_id':None,'control_protocol':1}
            response=transport.request('/worker/connect',hello)
            self.assertIsNone(response['lease'])
            binding={key:hello[key] for key in ('version','vm_id','instance_id','session_id')}
            binding.update({key:response[key] for key in ('connection_id','gateway_epoch')})
            binding['control_id']=None
            self.workers[vm_id]={'identity':identity,'hello':hello,'binding':binding,'transport':transport,
                'enrollment':enrollment,'guard':ReplayGuard(self.root/(vm_id+'.sqlite3'))}
            self.registry.authorize_lease(vm_id,'42',120)
            claim=self.registry.claim(vm_id,'42',120)
            self.assertTrue(claim['claimed'])
            self.workers[vm_id]['workflow_token']=claim['workflow_token']
            binding['control_id']=self.registry.control_public(vm_id)['control_id']
            transport.request('/worker/heartbeat',{**binding,'desktop_state':'ready'})

    def cleanup_fixture(self):
        for worker in getattr(self,'workers',{}).values():
            worker['guard'].close()
        if getattr(self,'holder',{}).get('server'):
            self.holder['loop'].call_soon_threadsafe(setattr,self.holder['server'],'should_exit',True)
            self.thread.join(5)
            self.assertFalse(self.thread.is_alive(),'Disposable TLS fixture did not stop')
        self.registry.close()
        self.temp.cleanup()

    def dispatch(self,vm_id,subject='42'):
        coroutine=self.holder['channel'].request('reach_get_screen_info',{},vm_id,subject,self.workers[vm_id]['workflow_token'])
        return asyncio.run_coroutine_threadsafe(coroutine,self.holder['loop'])

    def result(self,packet):
        return {**{key:packet[key] for key in CONNECTION_KEYS|{'lease_id','job_id'}},
            'failed':False,'result':{'content':[{'type':'text','text':packet['vm_id']}],'isError':False}}

    def test_three_real_tls_clients_target_isolation_replay_revocation(self):
        ids=list(self.workers)
        futures={vm_id:self.dispatch(vm_id) for vm_id in ids}
        packets={}
        for vm_id in ids:
            worker=self.workers[vm_id]
            packet=worker['transport'].request('/worker/next',{**worker['binding'],'desktop_state':'ready'})
            self.assertEqual(vm_id,packet['vm_id'])
            worker['guard'].accept(packet,worker['identity'],worker['binding'])
            packets[vm_id]=packet
        first=self.workers[ids[0]]
        with self.assertRaises(ChannelDenied):
            self.workers[ids[1]]['transport'].request('/worker/result',self.result(packets[ids[0]]))
        with self.assertRaises(ChannelDenied):
            first['guard'].accept(packets[ids[0]],first['identity'],first['binding'])
        for vm_id in reversed(ids):
            self.workers[vm_id]['transport'].request('/worker/result',self.result(packets[vm_id]))
        self.assertEqual(ids,[futures[vm_id].result(3)['content'][0]['text'] for vm_id in ids])
        with self.assertRaises(ChannelDenied):
            first['transport'].request('/worker/result',self.result(packets[ids[0]]))
        with self.assertRaises(ChannelDenied):
            first['enrollment'].request('/worker/enroll',first['identity'])
        with self.assertRaises(ChannelDenied):
            self.dispatch(ids[0],'43').result(3)
        first['transport'].request('/worker/revoke',{'version':2,'vm_id':ids[0]})
        with self.assertRaises(ChannelDenied):
            first['transport'].request('/worker/heartbeat',{**first['binding'],'desktop_state':'ready'})
        other=self.workers[ids[1]]
        self.assertIsNotNone(other['transport'].request('/worker/heartbeat',{**other['binding'],'desktop_state':'ready'})['lease'])

    def test_tls_hostname_pin_and_gateway_restart_fences_uncertain_action(self):
        first_id=next(iter(self.workers))
        worker=self.workers[first_id]
        with self.assertRaises(ChannelDenied):
            Transport({**self.config,'ca_sha256':'0'*64},'x'*43,self.root)
        mismatch=Transport({**self.config,'gateway':f'https://localhost:{self.port}'},'x'*43,self.root)
        with self.assertRaises(ssl.SSLCertVerificationError):
            mismatch.request('/worker/connect',worker['hello'])
        future=self.dispatch(first_id)
        packet=worker['transport'].request('/worker/next',{**worker['binding'],'desktop_state':'ready'})
        async def restart():
            channel=Channel(self.holder['registry'])
            self.holder['channel']=channel
            self.holder['app'].channel=channel
        asyncio.run_coroutine_threadsafe(restart(),self.holder['loop']).result(3)
        with self.assertRaises(ChannelDenied):
            future.result(3)
        with self.assertRaises(ChannelDenied):
            worker['transport'].request('/worker/result',self.result(packet))
        response=worker['transport'].request('/worker/connect',worker['hello'])
        self.assertIsNone(response['lease'])
        state=self.registry.db.execute('SELECT state FROM jobs WHERE job_id=?',(packet['job_id'],)).fetchone()[0]
        self.assertEqual('outcome_uncertain',state)
        with self.assertRaises(ChannelDenied):
            self.dispatch(first_id).result(3)


if __name__=='__main__':
    unittest.main()
