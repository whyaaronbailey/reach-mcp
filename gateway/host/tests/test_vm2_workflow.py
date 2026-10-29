"""VM2 claim fencing and owner-ledger scoping; local synthetic evidence."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
import test_workflow as original
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'core'))
from owner_session_permissions import OwnerSessionPermissions, PermissionDenied, vm_scope

class Vm2ClaimTests(original.ClaimTests):
    def setUp(self):
        self.vm = patch.object(original,'VM','vm-gamma'); self.vm.start()
        super().setUp()
    def tearDown(self):
        super().tearDown(); self.vm.stop()

class Vm2LedgerTests(unittest.TestCase):
    def setUp(self):
        self.p=OwnerSessionPermissions(':memory:')
        self.g=self.p.start_session('fixture','fixture-start')['generation']
    def tearDown(self): self.p.close()
    def consume(self,op,vm='vm-gamma'):
        return self.p.consume_operation('fixture',self.g,op,'a'*64,vm_id=vm)
    def test_all_three_explicit_and_default_scopes(self):
        self.assertEqual(vm_scope(None),vm_scope(['vm-gamma','vm-beta','vm-alpha']))
        self.p.approve_session('fixture',self.g,'fixture-owner',None)
        for n,vm in enumerate(vm_scope(None)): self.consume('op'+str(n),vm)
    def test_vm2_only_and_revocation(self):
        self.p.approve_session('fixture',self.g,'fixture-owner',['vm-gamma'])
        for n in range(5): self.consume('op'+str(n))
        for vm in ('vm-beta','vm-alpha'):
            with self.assertRaises(PermissionDenied): self.consume('cross-'+vm,vm)
        self.p.revoke_session('fixture',self.g,'fixture-revoke')
        with self.assertRaises(PermissionDenied): self.consume('after-revoke')
    def test_once_needs_exact_vm_and_cannot_replay(self):
        self.p.approve_operation('fixture',self.g,'once','a'*64,'fixture-owner',vm_id='vm-gamma')
        with self.assertRaises(PermissionDenied): self.consume('once','vm-beta')
        self.consume('once')
        with self.assertRaises(PermissionDenied): self.consume('once')
        with self.assertRaises(PermissionDenied): self.consume('twice')
    def test_end_and_replacement_cannot_reuse_grant(self):
        self.p.approve_session('fixture',self.g,'fixture-owner',['vm-gamma'])
        self.p.end_session('fixture',self.g,'fixture-end')
        with self.assertRaises(PermissionDenied): self.consume('ended')
        self.g=self.p.start_session('fixture','fixture-restart')['generation']
        with self.assertRaises(PermissionDenied): self.consume('replacement')
    def test_unknown_vm_is_refused(self):
        with self.assertRaises(PermissionDenied): vm_scope(['vm-unknown'])

if __name__=='__main__': unittest.main()
