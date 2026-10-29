"""Policy/proof tests use simulated observations, never real boundary acceptance."""
import asyncio
import copy
import hashlib
import json
import ipaddress
import unittest
from unittest.mock import Mock, patch

import deployment_policy as dp
from channel import ChannelDenied
from registry import Registry

# Synthetic tailnet fixtures derived from the standard CGNAT range.
TEST_TAILNET = ipaddress.ip_network('100.64.0.0/10')

BOOT='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
OBS={'host_boot_id':BOOT,'container_hostname':'1'*12}


def fixture_policy():
    transport=json.dumps({'version':2,'private_urls':['https://nexus.example.test:19444']}).encode()
    return {'version':1,'deployment_id':'a'*32,'manifest_sha256':'b'*64,
        'transport_sha256':hashlib.sha256(transport).hexdigest(),'image_id':'sha256:'+'c'*64,
        'checker_sha256':'d'*64,'container_spec_sha256':'e'*64,
        'hostname_mode':'docker-container-id-prefix','runtime_root':'/srv/reach/runtime',
        'tls':{'ca_sha256':hashlib.sha256(b'ca').hexdigest(),
            'leaf_sha256':hashlib.sha256(b'leaf').hexdigest(),
            'private_urls':['https://nexus.example.test:19444']},
        'public':{'origin':'https://nexus.example.test','mcp_path':'/reach/mcp','oauth_prefix':'/auth/reach'},
        'network':{'name':'reach-auth','subnet':'198.51.100.0/24',
                   'gateway':'198.51.100.1','container_ip':'198.51.100.2'}}


def fixture_profile(index=1):
    return {'version':1,'vm_id':'vm-'+str(index),
        'machine_uuid':str(index)*8+'-'+str(index)*4+'-4'+str(index)*3+'-8'+str(index)*3+'-'+str(index)*12,
        'account_sid':'S-1-5-21-111-222-333-'+str(1000+index),'enabled':True,
        'kind':'windows-tailnet','worker_url':'https://nexus.example.test:19444',
        'source_addresses':[str(TEST_TAILNET[index])],'guest_policy_sha256':'f'*64,
        'adapter':{'node_id':'node'+str(index),'node_key':'nodekey:'+str(index)*64,'interface':'tailscale0'}}


def fixture_runtime(shared,now=1000):
    return {'version':1,'deployment_id':shared['deployment_id'],'policy_sha256':dp.digest(shared),
        'checked_at':now,'host_boot_id':BOOT,'container_id':'1'*64,'image_id':shared['image_id'],
        'network_id':'2'*64,'container_hostname':'1'*12,
        'container_spec_sha256':shared['container_spec_sha256'],'shared_rules_sha256':'3'*64,
        **{flag:True for flag in dp.RUNTIME_FLAGS}}


def fixture_proof(shared,selected,attestation,connection,now=1000):
    return {'version':3,**{key:selected[key] for key in ('vm_id','machine_uuid','account_sid')},
        **{key:connection[key] for key in ('connection_id','gateway_epoch')},
        'checked_at':now,**{key:shared[key] for key in ('manifest_sha256','transport_sha256','checker_sha256')},
        'policy_sha256':dp.digest(shared),'profile_sha256':dp.digest(selected),
        'runtime_sha256':dp.digest(attestation),
        **{key:attestation[key] for key in ('host_boot_id','container_id','network_id')},
        'observation_id':'4'*32,**{flag:True for flag in dp.PROOF_FLAGS}}


class DeploymentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.shared=fixture_policy()
        self.runtime=fixture_runtime(self.shared)

    def test_shared_policy_contains_no_vm_list_and_profiles_are_independent(self):
        before=dp.digest(dp.policy(self.shared))
        one=fixture_profile(1);two=fixture_profile(2);three=fixture_profile(3)
        one_hash=dp.digest(dp.profile(one,self.shared))
        for selected in (two,three):
            dp.profile(selected,self.shared)
        two['enabled']=False
        dp.profile(two,self.shared)
        self.assertEqual(before,dp.digest(self.shared))
        self.assertEqual(one_hash,dp.digest(one))
        with self.assertRaises(ChannelDenied):
            dp.policy({**self.shared,'vms':[one,two,three]})

    def test_both_supported_transport_kinds_are_data_driven(self):
        selected=fixture_profile()
        selected['kind']='libvirt-isolated'
        selected['source_addresses']=['192.0.2.10']
        selected['adapter']={'domain_uuid':selected['machine_uuid'],'network_name':'future-private',
            'nwfilter_name':'future-filter','nwfilter_sha256':'5'*64,'mac_address':'02:00:00:00:00:02'}
        dp.profile(selected,self.shared)
        selected['adapter']['domain_uuid']='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        dp.profile(selected,self.shared)  # Explicit SMBIOS override is data, not a fork.
        with self.assertRaises(ChannelDenied):
            dp.profile({**selected,'kind':'linux'},self.shared)

    def test_tailnet_interfaces_are_explicit_data_and_bounded(self):
        selected=fixture_profile()
        shared_digest=dp.digest(self.shared)
        for name in ('tailscale0','tailscale1','tailscale42','tailscale999999'):
            selected['adapter']['interface']=name
            self.assertEqual(dp.profile(selected,self.shared)['adapter']['interface'],name)
        self.assertEqual(dp.digest(self.shared),shared_digest)
        for name in ('eth0','tailscale','tailscale-1','tailscale1000000','tailscale1;id','../tailscale1',None):
            selected['adapter']['interface']=name
            with self.subTest(interface=name),self.assertRaises(ChannelDenied):
                dp.profile(selected,self.shared)

    def test_profile_addresses_never_substitute_for_stable_identity(self):
        selected=fixture_profile()
        for field,bad in (('vm_id','../escape'),('machine_uuid',str(TEST_TAILNET[1])),
                          ('account_sid','ReachAgent'),('worker_url','http://nexus.example.test:19444')):
            with self.subTest(field=field),self.assertRaises(ChannelDenied):
                dp.profile({**selected,field:bad},self.shared)
        selected['adapter']['node_id']=''
        with self.assertRaises(ChannelDenied):
            dp.profile(selected,self.shared)

    def test_boot_container_image_network_generation_and_guard_fences(self):
        dp.runtime(self.runtime,self.shared,now=1000,fresh=True,**OBS)
        variants={'host_boot_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            'container_id':'9'*64,'container_hostname':'wrong','policy_sha256':'9'*64,
            'image_id':'sha256:'+'9'*64,'container_spec_sha256':'9'*64,
            **{flag:False for flag in dp.RUNTIME_FLAGS}}
        for field,bad in variants.items():
            with self.subTest(field=field),self.assertRaises(ChannelDenied):
                dp.runtime({**self.runtime,field:bad},self.shared,now=1000,**OBS)
        for observation in ({**OBS,'container_hostname':'9'*12},
                            {**OBS,'host_boot_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'}):
            with self.assertRaises(ChannelDenied):
                dp.runtime(self.runtime,self.shared,now=1000,**observation)

    def test_start_requires_fresh_attestation_but_running_container_can_age(self):
        with self.assertRaises(ChannelDenied):
            dp.runtime(self.runtime,self.shared,now=1121,fresh=True,**OBS)
        dp.runtime(self.runtime,self.shared,now=1121,fresh=False,**OBS)
        with self.assertRaises(ChannelDenied):
            dp.runtime({**self.runtime,'checked_at':True},self.shared,now=1000,**OBS)
        with self.assertRaises(ChannelDenied):
            dp.policy({**self.shared,'hostname_mode':'whatever-docker-happens-to-use'})

    def test_context_binds_actual_transport_and_tls_files(self):
        transport=json.dumps({'version':2,'private_urls':self.shared['tls']['private_urls']}).encode()
        json_files={'/run/config/deployment-policy.json':self.shared,
                    '/run/config/runtime-attestation.json':self.runtime,
                    '/run/config/security.json':{key:self.shared[key] for key in ('manifest_sha256','transport_sha256')}}
        binary_files={'/run/config/transport.json':transport,'/run/tls/ca.crt':b'ca','/run/tls/server.crt':b'leaf'}
        read_json=lambda path:json_files[path]
        read_bytes=lambda path,maximum:binary_files[path]
        dp.deployment_context(read_json,read_bytes,now=1000,fresh=True,observation=OBS)
        for path in binary_files:
            original=binary_files[path];binary_files[path]=original+b'tamper'
            with self.subTest(path=path),self.assertRaises(ChannelDenied):
                dp.deployment_context(read_json,read_bytes,now=1000,fresh=True,observation=OBS)
            binary_files[path]=original

    def test_service_gate_precedes_database_or_listener_construction(self):
        import service
        with patch.object(service,'deployment_context',side_effect=ChannelDenied()),\
                patch.object(service,'Registry') as registry,patch('uvicorn.Server') as server:
            with self.assertRaises(ChannelDenied):
                asyncio.run(service.main())
            registry.assert_not_called();server.assert_not_called()


class IndependentProofTests(unittest.TestCase):
    def setUp(self):
        self.now=1000
        self.registry=Registry(':memory:',clock=lambda:self.now)
        self.epoch=self.registry.start_gateway()
        self.shared=fixture_policy();self.runtime=fixture_runtime(self.shared)
        self.profiles={};self.proofs={}
        for index in range(1,4):
            selected=fixture_profile(index);vm_id=selected['vm_id']
            identity={'version':2,**{key:selected[key] for key in ('vm_id','machine_uuid','account_sid')}}
            grant=self.registry.grant(vm_id,vm_id,selected['machine_uuid'],selected['account_sid'],['123'])
            credential=self.registry.enroll('Bearer '+grant['enrollment_token'],identity)
            connection=self.registry.connect('Bearer '+credential['worker_token'],
                {**identity,'instance_id':str(index)*32,'session_id':'session-'+str(index),'desktop_state':'ready','control_id':None,'control_protocol':1},self.epoch)
            self.profiles[vm_id]=selected
            self.proofs[vm_id]=fixture_proof(self.shared,selected,self.runtime,connection)

    def tearDown(self):
        self.registry.close()

    def verify(self,vm_id,proof=None,selected=None,attestation=None):
        return dp.verify_network_proof(self.registry,vm_id,proof or self.proofs[vm_id],
            self.shared,selected or self.profiles[vm_id],attestation or self.runtime,observation=OBS,now=self.now)

    def test_third_identity_and_independent_revocation_without_shared_digest_churn(self):
        shared_hash=dp.digest(self.shared)
        for vm_id in self.profiles:
            self.verify(vm_id)
            self.assertIsNone(self.registry.lease_public(vm_id))
        self.registry.revoke('vm-2');self.profiles['vm-2']['enabled']=False
        with self.assertRaises(ChannelDenied):self.verify('vm-2')
        self.verify('vm-1');self.verify('vm-3')
        self.assertEqual(shared_hash,dp.digest(self.shared))

    def test_wrong_vm_wrong_profile_and_replaced_runtime_proof_rejected(self):
        with self.assertRaises(ChannelDenied):self.verify('vm-1',proof=self.proofs['vm-2'])
        with self.assertRaises(ChannelDenied):self.verify('vm-1',selected=self.profiles['vm-2'])
        changed=copy.deepcopy(self.runtime);changed['network_id']='9'*64
        with self.assertRaises(ChannelDenied):self.verify('vm-1',attestation=changed)
        changed=copy.deepcopy(self.profiles['vm-1']);changed['source_addresses']=[str(TEST_TAILNET[9])]
        with self.assertRaises(ChannelDenied):self.verify('vm-1',selected=changed)

    def test_old_schema_partial_boolean_only_and_replayed_proof_fail_closed(self):
        for invalid in ({'version':2,**{flag:True for flag in dp.PROOF_FLAGS}},
                        {**self.proofs['vm-1'],'version':2},
                        {**self.proofs['vm-1'],'checked_at':879},
                        {**self.proofs['vm-1'],'tls_verified':1}):
            with self.assertRaises(ChannelDenied):self.verify('vm-1',proof=invalid)
        self.registry.start_gateway()
        with self.assertRaises(ChannelDenied):self.verify('vm-1')


if __name__=='__main__':
    unittest.main()
