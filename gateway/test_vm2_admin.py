"""The existing approval/nonce/revoke matrix also applies to VM-GAMMA."""
import test_admin_frontend as original
from channel import ChannelDenied

class Vm2AdminTests(original.AdminFrontendTests):
    def setUp(self):
        super().setUp()
        self.registry.vm_id = self.args['vm_id'] = 'vm-gamma'

    async def test_vm2_token_cannot_authorize_other_vm(self):
        for target in ('vm-alpha','vm-beta','vm-unknown'):
            with self.assertRaises(ChannelDenied):
                await self.front.run('reach_run_admin',{**self.args,'vm_id':target},'42',original.context())
        self.assertFalse(self.broker.calls)
