"""Real SQLite projection plus negative restart-evidence fixtures; no live access."""
import copy
import json
import sqlite3
import unittest
import restart_acceptance as r

class RestartEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.executescript("""
        CREATE TABLE settings(key,value);
        CREATE TABLE vms(vm_id,machine_uuid,account_sid,credential_id,revoked,token_hash,subjects_json);
        CREATE TABLE connections(vm_id,connection_id,gateway_epoch,last_seen,desktop_state,control_id);
        CREATE TABLE leases(vm_id,lease_id,gateway_epoch,expires_at,subject);
        CREATE TABLE reservations(vm_id,control_id,expires_at,token_hash);
        CREATE TABLE jobs(job_id,vm_id,lease_id,gateway_epoch,state,created_at,deadline,tool,control_id);
        INSERT INTO settings VALUES('gateway_epoch','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
        INSERT INTO vms VALUES('one','uuid','sid','credential',0,'PRIVATE_CREDENTIAL_CANARY','PRIVATE_SUBJECT_CANARY');
        INSERT INTO connections VALUES('one','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',995,'locked',NULL);
        INSERT INTO leases VALUES('one','lease','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1050,'PRIVATE_SUBJECT_CANARY');
        INSERT INTO jobs VALUES('j','one','old','old','completed',900,990,'reach_get_capabilities','old');
        """)
        self.before = r.snapshot(self.db, 1000)
        self.after = copy.deepcopy(self.before)
        self.after.update(captured_at=1010, gateway_epoch="c"*32, leases=[])
        self.after["connections"] = [["one", "d"*32, "c"*32, 1009, "signed_out", None]]

    def tearDown(self):
        self.db.close()

    def reject(self, value, reason, before=None):
        with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
            r.compare(self.before if before is None else before, value)

    def test_real_sqlite_projection_has_no_credential_or_subject(self):
        text = json.dumps(self.before)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("uuid", text)
        self.assertNotIn("sid", text)
        self.assertNotIn("token_hash", text)
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute("DELETE FROM vms")

    def test_restart_renews_connections_and_clears_actual_lease(self):
        out = r.compare(self.before, self.after)
        self.assertTrue(out["lease_invalidation_exercised"])
        self.assertFalse(out["desktop_acceptance"])
        self.assertFalse(out["automatic_boot_recovery_accepted"])
        self.assertFalse(out["uncertain_desktop_replay_tested"])
        self.assertEqual(out["gateway_restart_acceptance"], "passed")

    def test_expired_lease_does_not_claim_authority_exercised(self):
        self.before["leases"][0][3] = 999
        self.assertFalse(r.compare(self.before, self.after)["lease_invalidation_exercised"])

    def test_same_epoch_refuses(self):
        self.after["gateway_epoch"] = "a"*32
        self.after["connections"][0][2] = "a"*32
        self.reject(self.after, "gateway-did-not-restart")

    def test_active_claim_before_refuses(self):
        before = copy.deepcopy(self.before)
        before["reservations"] = [["one", "e"*32, 1100]]
        self.reject(self.after, "workflow-must-be-released", before)

    def test_native_context_without_claim_still_refuses(self):
        before = copy.deepcopy(self.before)
        before["connections"][0][5] = "e"*32
        self.reject(self.after, "native-teardown-not-acknowledged", before)

    def test_queued_and_delivered_before_refuse(self):
        for state in ("queued", "delivered"):
            with self.subTest(state=state):
                before = copy.deepcopy(self.before)
                before["job_states"][state] = 1
                self.reject(self.after, "inflight-operation", before)

    def test_missing_worker_refuses(self):
        self.after["connections"] = []
        self.reject(self.after, "all-enrolled-workers-must-be-connected")

    def test_stale_worker_refuses(self):
        self.after["connections"][0][3] = 960
        self.reject(self.after, "worker-heartbeat-stale")

    def test_current_fractional_second_heartbeat_is_valid(self):
        self.after["connections"][0][3] = self.after["captured_at"] + 0.9
        self.assertEqual(r.compare(self.before,self.after)["gateway_restart_acceptance"],"passed")

    def test_future_worker_heartbeat_refuses(self):
        self.after["connections"][0][3] = 1020
        self.reject(self.after, "worker-heartbeat-stale")

    def test_lease_survival_refuses(self):
        self.after["leases"] = copy.deepcopy(self.before["leases"])
        self.reject(self.after, "authority-survived-restart")

    def test_identity_change_refuses(self):
        self.after["vm_identity_sha256"] = "e"*64
        self.reject(self.after, "vm-identity-changed")

    def test_job_change_refuses(self):
        self.after["job_records_sha256"] = "e"*64
        self.reject(self.after, "historical-job-records-changed")

    def test_old_connection_reuse_refuses(self):
        self.after["connections"][0][1] = "b"*32
        self.reject(self.after, "old-worker-connection-reused")

    def test_long_gap_refuses(self):
        self.after["captured_at"] = 2000
        self.after["connections"][0][3] = 2000
        self.reject(self.after, "restart-observation-window")

    def test_wrong_image_refuses(self):
        self.after["image_id"] = "sha256:"+"e"*64
        self.reject(self.after, "release-binding")

    def test_no_live_identity_refuses(self):
        self.after["active_vm_ids"] = []
        self.reject(self.after, "enrolled-live-worker-required")

    def test_two_independent_workers_both_must_reconnect(self):
        for value, epoch, conn in ((self.before,"a"*32,"e"*32),(self.after,"c"*32,"f"*32)):
            value["active_vm_ids"].append("two")
            value["connections"].append(["two",conn,epoch,value["captured_at"],"ready",None])
        self.assertEqual(r.compare(self.before,self.after)["vm_ids"],["one","two"])
        self.after["connections"][1][1] = "e"*32
        self.reject(self.after,"old-worker-connection-reused")


class PersistentRestartEvidenceTests(unittest.TestCase):
    """Use the real registry to verify only fresh, standing-authorized sessions pass."""
    def setUp(self):
        from channel import Channel
        from test_registry import Fixture
        self.fixture = Fixture(count=1)
        self.registry = self.fixture.registry
        self.worker = self.fixture.workers['vm-fixture-1']
        self.binding = {'policy_sha256':'a'*64,'profile_sha256':'b'*64,'security_sha256':'c'*64}
        self.registry.authorization_context = lambda vm_id: dict(self.binding)
        connection = self.registry.owner_connection('vm-fixture-1')
        self.registry.authorize_persistent('vm-fixture-1','42',self.binding,
            {key:connection[key] for key in ('connection_id','gateway_epoch')})
        self.before = self.snapshot()
        self.fixture.clock.now += 5
        self.fixture.channel = Channel(self.registry)
        hello = self.fixture.channel.worker_connect(self.worker['auth'],self.worker['hello'])
        self.worker['poll'].update({key:hello[key] for key in ('connection_id','gateway_epoch')})
        self.after = self.snapshot()

    def snapshot(self):
        db = sqlite3.connect('file:'+self.fixture.path.as_posix()+'?mode=ro',uri=True)
        try:
            return r.snapshot(db,self.fixture.clock.now)
        finally:
            db.close()

    def tearDown(self):
        self.fixture.close()

    def reject(self, after, reason):
        with self.assertRaisesRegex(ValueError, '^'+reason+'$'):
            r.compare(self.before,after)

    def test_fresh_session_with_unchanged_standing_grant_passes(self):
        out = r.compare(self.before,self.after)
        self.assertEqual('passed',out['gateway_restart_acceptance'])
        self.assertTrue(out['persistent_authorizations_preserved'])
        self.assertEqual(['vm-fixture-1'],out['persistent_sessions_reauthorized'])
        self.assertEqual(1,out['leases_after'])
        self.assertTrue(out['lease_invalidation_exercised'])
        self.assertNotEqual(self.before['leases'][0][1],self.after['leases'][0][1])

    def test_standing_projection_does_not_export_subject_identity_or_verifiers(self):
        serialized = json.dumps(self.after)
        for value in ('token_hash','subjects_json','machine_uuid','account_sid',self.worker['auth'],
                      self.worker['identity']['machine_uuid'],self.worker['identity']['account_sid']):
            self.assertNotIn(value,serialized)

    def test_new_lease_without_standing_consent_refuses(self):
        after = copy.deepcopy(self.after)
        after['persistent_authorizations'] = []
        self.reject(after,'standing-authorization-changed')
        after = copy.deepcopy(self.after)
        del after['persistent_authorizations']
        self.reject(after,'persistence-evidence-missing')

    def test_standing_consent_drift_refuses(self):
        after = copy.deepcopy(self.after)
        after['persistent_authorizations'][0]['binding_sha256'] = 'd'*64
        self.reject(after,'standing-authorization-changed')

    def test_reused_old_lease_or_old_issue_time_refuses(self):
        after = copy.deepcopy(self.after)
        after['leases'][0][1] = after['lease_bindings'][0][1] = self.before['leases'][0][1]
        self.reject(after,'authority-survived-restart')
        after = copy.deepcopy(self.after)
        after['lease_bindings'][0][2] = self.before['captured_at']-1
        self.reject(after,'authority-survived-restart')

    def test_full_session_epoch_instance_and_grant_binding_required(self):
        for column in (3,4,5,6,7):
            with self.subTest(column=column):
                after = copy.deepcopy(self.after)
                after['lease_bindings'][0][column] = 'e'*32
                self.reject(after,'fresh-session-binding')

    def test_expired_or_unbounded_fresh_lease_refuses(self):
        for expiry in (self.after['captured_at'],self.after['lease_bindings'][0][2]+7201):
            with self.subTest(expiry=expiry):
                after = copy.deepcopy(self.after)
                after['leases'][0][3] = expiry
                self.reject(after,'authority-survived-restart')

    def test_ready_standing_grant_must_have_reauthorized_lease(self):
        after = copy.deepcopy(self.after)
        after['leases'] = []
        after['lease_bindings'] = []
        self.reject(after,'persistent-reauthorization-missing')

    def test_mismatched_real_lease_subject_cannot_borrow_standing_grant(self):
        self.registry.db.execute("UPDATE leases SET subject='43'")
        after = self.snapshot()
        self.assertIsNone(after['lease_bindings'][0][7])
        self.reject(after,'fresh-session-binding')

    def test_missing_extended_bindings_refuse(self):
        for key in ('lease_bindings','connection_bindings'):
            after = copy.deepcopy(self.after)
            del after[key]
            self.reject(after,'persistence-evidence-missing')

    def test_paused_or_identity_mismatched_standing_grant_never_permits_lease(self):
        for field,value in (('paused',True),('identity_matches',False)):
            with self.subTest(field=field):
                before,after = copy.deepcopy(self.before),copy.deepcopy(self.after)
                before['persistent_authorizations'][0][field] = value
                after['persistent_authorizations'][0][field] = value
                with self.assertRaisesRegex(ValueError,'^standing-authorization-binding$'):
                    r.compare(before,after)

    def test_paused_standing_grant_may_survive_without_authority(self):
        before,after = copy.deepcopy(self.before),copy.deepcopy(self.after)
        for value in (before,after):
            value['persistent_authorizations'][0]['paused'] = True
            value['leases'] = []
            value['lease_bindings'] = []
        out = r.compare(before,after)
        self.assertTrue(out['persistent_authorizations_preserved'])
        self.assertEqual([],out['persistent_sessions_reauthorized'])

if __name__ == "__main__":
    unittest.main()
