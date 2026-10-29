"""Owner CLI security and proof binding tests; no real owner files or leases."""
import copy
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import admin
from channel import ChannelDenied
from registry import Registry
from test_deployment_policy import (fixture_policy,fixture_profile,fixture_runtime,
                                    fixture_proof,OBS)


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.registry = Registry(':memory:', clock=lambda: self.now)
        self.epoch = self.registry.start_gateway()
        self.identity = {'version':2,'vm_id':'vm-test','machine_uuid':'11111111-1111-4111-8111-111111111111',
                         'account_sid':'S-1-5-21-111-222-333-1001'}
        grant = self.registry.grant('vm-test','Test',self.identity['machine_uuid'],
                                    self.identity['account_sid'],['123'])
        self.credential = self.registry.enroll('Bearer '+grant['enrollment_token'], self.identity)
        self.connect = {**self.identity,'instance_id':'a'*32,'session_id':'session-1','desktop_state':'ready','control_protocol':1,'control_id':None}
        self.connection = self.registry.connect('Bearer '+self.credential['worker_token'],self.connect,self.epoch)
        self.shared=fixture_policy()
        self.selected={**fixture_profile(),'vm_id':'vm-test'}
        self.runtime=fixture_runtime(self.shared)
        self.proof=fixture_proof(self.shared,self.selected,self.runtime,self.connection)

    def tearDown(self):
        self.registry.close()

    def verify(self, proof=None):
        return admin.verify_network_proof(self.registry,'vm-test',proof or self.proof,self.shared,
            self.selected,self.runtime,observation=OBS,now=self.now)

    def test_current_proof_does_not_itself_grant_desktop_access(self):
        self.verify()
        self.assertIsNone(self.registry.lease_public('vm-test'))

    def test_each_identity_or_boundary_mismatch_is_rejected(self):
        differences = {
            'vm_id':'vm-other',
            'machine_uuid':'22222222-2222-4222-8222-222222222222',
            'account_sid':'S-1-5-21-111-222-333-1002',
            'connection_id':'f'*32, 'gateway_epoch':'e'*32,
            'manifest_sha256':'d'*64, 'transport_sha256':'d'*64,
            'tls_verified':False, 'guest_filter_verified':False,
            'host_filter_verified':False, 'container_egress_verified':False,
            'private_routes_not_public':False,
        }
        for field,value in differences.items():
            with self.subTest(field=field), self.assertRaises(ChannelDenied):
                self.verify({**self.proof,field:value})

    def test_stale_future_and_boolean_timestamps_rejected(self):
        for timestamp in (self.now-121,self.now+11,True):
            with self.subTest(timestamp=timestamp), self.assertRaises(ChannelDenied):
                self.verify({**self.proof,'checked_at':timestamp})

    def test_revocation_invalidates_formerly_valid_proof(self):
        self.verify()
        self.registry.revoke('vm-test')
        with self.assertRaises(ChannelDenied):
            self.verify()

    def test_restart_invalidates_formerly_valid_proof(self):
        self.verify()
        epoch = self.registry.start_gateway()
        self.registry.connect('Bearer '+self.credential['worker_token'],self.connect,epoch)
        with self.assertRaises(ChannelDenied):
            self.verify()

    def test_offline_connection_cannot_use_freshly_dated_old_proof(self):
        self.now += 46
        with self.assertRaises(ChannelDenied):
            self.verify({**self.proof,'checked_at':self.now})

    def test_unapproved_subject_cannot_lease_even_with_valid_proof(self):
        self.verify()
        with self.assertRaises(ChannelDenied):
            self.registry.authorize_lease('vm-test','456',60)


class CliTests(unittest.TestCase):
    def test_path_traversal_rejected_before_file_or_database_access(self):
        for identity in ('../security','vm-test/../../secret','/etc/shadow','VM-TEST','vm_test'):
            with self.subTest(identity=identity), patch.object(sys,'argv',
                    ['admin.py','lease','--vm-id',identity,'--subject','123']), \
                    patch.object(admin,'Registry') as registry, patch.object(admin,'protected_file') as protected:
                with self.assertRaises(ChannelDenied):
                    admin.main()
                registry.assert_not_called()
                protected.assert_not_called()

    def test_invalid_output_does_not_mint_or_invalidate_grants(self):
        request = {'version':2,'vm_id':'vm-test','display_name':'Test',
                   'machine_uuid':'11111111-1111-4111-8111-111111111111',
                   'account_sid':'S-1-5-21-111-222-333-1001'}
        registry = Mock()
        with patch.object(sys,'argv',['admin.py','grant','--request','/safe/request.json',
                '--subject','123','--out','/unsafe/grant.json']), \
                patch.object(admin,'Registry',return_value=registry), \
                patch.object(admin,'protected_file',side_effect=lambda path: request if path=='/safe/request.json'
                    else (fixture_policy() if path.endswith('deployment-policy.json')
                          else {**fixture_profile(),'vm_id':'vm-test'})), \
                patch.object(admin,'secret_output',side_effect=ValueError('unsafe output')):
            with self.assertRaises(ValueError):
                admin.main()
        registry.grant.assert_not_called()
        registry.close.assert_called_once()


def info(mode, owner=0):
    return os.stat_result((mode,1,1,1,owner,0,1,0,0,0))


class OwnerPathTests(unittest.TestCase):
    def test_symlink_ancestor_rejected_before_open(self):
        path = Path(os.path.abspath('owner/link/proof.json'))
        link = path.parent
        def fake_stat(value):
            return info((stat.S_IFLNK | 0o777) if value == link else (stat.S_IFDIR | 0o755))
        with patch.object(admin.os,'geteuid',return_value=0,create=True), \
                patch.object(Path,'lstat',fake_stat), patch.object(admin.os,'open') as opened:
            with self.assertRaises(ValueError):
                admin.protected_bytes(path)
            opened.assert_not_called()

    def test_writable_or_foreign_owned_ancestor_rejected(self):
        path = Path(os.path.abspath('owner/input/proof.json'))
        for mode,owner in ((stat.S_IFDIR|0o777,0),(stat.S_IFDIR|0o755,555)):
            with self.subTest(mode=mode,owner=owner), \
                    patch.object(admin.os,'geteuid',return_value=10008,create=True), \
                    patch.object(Path,'lstat',return_value=info(mode,owner)):
                with self.assertRaises(ValueError):
                    admin._parent_chain(path)

    def test_grant_parent_must_be_private(self):
        with patch.object(admin.os,'geteuid',return_value=0,create=True), \
                patch.object(Path,'lstat',return_value=info(stat.S_IFDIR|0o755)):
            with self.assertRaises(ValueError):
                admin._parent_chain(Path(os.path.abspath('owner/output/grant.json')),private_parent=True)

    def test_existing_grant_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'grant.json'
            target.write_bytes(b'original')
            with patch.object(admin,'_parent_chain',return_value=target):
                with self.assertRaises(FileExistsError):
                    admin.write_secret(target,{'replacement':True})
            self.assertEqual(target.read_bytes(),b'original')

    def test_oversized_input_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'proof.json'
            target.write_bytes(b'x'*32)
            with patch.object(admin,'_parent_chain',return_value=target), \
                    patch.object(admin,'_trusted'):
                with self.assertRaises(ValueError):
                    admin.protected_file(target,maximum=16)


if __name__ == '__main__':
    unittest.main()
