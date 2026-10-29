"""Read-only, fixed-path evidence for the reviewed image6 gateway restart.

This does not stop/start services, mint leases, dispatch tools, or write SQLite.
A live test requires already enrolled, connected workers in idle native contexts.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import time

MAX_ROWS = 100000
MAX_BYTES = 1048576
MAX_SESSION_LEASE = 7200
IMAGE = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
CONTAINER = "0000000000000000000000000000000000000000000000000000000000000000"

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

def rows(db, sql):
    result = db.execute(sql + " LIMIT 100001").fetchall()
    need(len(result) <= MAX_ROWS, "row-bound")
    return [list(row) for row in result]

def persistence_snapshot(db):
    """Project standing consent and session binding without identities or subjects."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='desktop_authorizations'").fetchone() is None:
        return {}
    authorizations = rows(db, "SELECT vm_id,grant_id,subject,machine_uuid,account_sid,context_json,paused,created_at FROM desktop_authorizations ORDER BY vm_id")
    identities = {row[0]: row for row in rows(db, "SELECT vm_id,machine_uuid,account_sid,subjects_json,revoked FROM vms ORDER BY vm_id")}
    grants, valid = [], {}
    for vm_id, grant_id, subject, machine, sid, context, paused, created in authorizations:
        vm = identities.get(vm_id)
        try:
            parsed = json.loads(context)
            context_valid = (type(parsed) is dict and set(parsed) == {'policy_sha256','profile_sha256','security_sha256'}
                             and all(isinstance(item,str) and re.fullmatch(r'[a-f0-9]{64}',item) for item in parsed.values()))
            identity_matches = bool(vm and not vm[4] and (machine,sid) == (vm[1],vm[2])
                                    and subject in json.loads(vm[3]) and context_valid)
        except (ValueError, TypeError):
            identity_matches = False
        grants.append({'vm_id':vm_id,'grant_id':grant_id,'binding_sha256':digest([subject,machine,sid,context]),
                       'paused':bool(paused),'created_at':created,'identity_matches':identity_matches})
        if identity_matches and not paused:
            valid[vm_id] = (grant_id,subject)
    leases = rows(db, "SELECT vm_id,lease_id,issued_at,instance_id,session_id,connection_id,gateway_epoch,subject FROM leases ORDER BY vm_id")
    bindings = []
    for *binding, subject in leases:
        grant = valid.get(binding[0])
        bindings.append([*binding,grant[0] if grant and subject == grant[1] else None])
    return {'persistent_authorizations':grants,'lease_bindings':bindings,
            'connection_bindings':rows(db, "SELECT vm_id,instance_id,session_id,connection_id,gateway_epoch FROM connections ORDER BY vm_id")}

def snapshot(db, now=None):
    now = int(time.time() if now is None else now)
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    try:
        row = db.execute("SELECT value FROM settings WHERE key='gateway_epoch'").fetchone()
        need(row is not None and re.fullmatch(r"[a-f0-9]{32}", row[0]), "gateway-epoch")
        epoch = row[0]
        # Explicit projections never select credential/capability verifier columns.
        identities = rows(db, "SELECT vm_id,machine_uuid,account_sid,credential_id,revoked FROM vms ORDER BY vm_id")
        active = [row[0] for row in identities if row[4] == 0]
        connections = rows(db, "SELECT vm_id,connection_id,gateway_epoch,last_seen,desktop_state,control_id FROM connections ORDER BY vm_id")
        leases = rows(db, "SELECT vm_id,lease_id,gateway_epoch,expires_at FROM leases ORDER BY vm_id")
        reservations = rows(db, "SELECT vm_id,control_id,expires_at FROM reservations ORDER BY vm_id")
        jobs = rows(db, "SELECT job_id,vm_id,lease_id,gateway_epoch,state,created_at,deadline,tool,control_id FROM jobs ORDER BY job_id")
        return {
            "version": 1, "image_id": IMAGE, "container_id": CONTAINER,
            "captured_at": now, "gateway_epoch": epoch, "active_vm_ids": active,
            "vm_identity_sha256": digest(identities), "connections": connections,
            "leases": leases, "reservations": reservations,
            "job_count": len(jobs), "job_states": dict(sorted(Counter(row[4] for row in jobs).items())),
            "job_records_sha256": digest(jobs),
            **persistence_snapshot(db),
        }
    finally:
        db.rollback()

def idle_gate(value):
    need(value["version"] == 1 and value["image_id"] == IMAGE and value["container_id"] == CONTAINER, "release-binding")
    active = value["active_vm_ids"]
    need(active and len(active) == len(set(active)), "enrolled-live-worker-required")
    need(value["reservations"] == [], "workflow-must-be-released")
    need(not value["job_states"].get("queued", 0) and not value["job_states"].get("delivered", 0), "inflight-operation")
    connections = value["connections"]
    need({row[0] for row in connections} == set(active) and len(connections) == len(active), "all-enrolled-workers-must-be-connected")
    for vm_id, connection_id, epoch, last_seen, desktop, control_id in connections:
        need(re.fullmatch(r"[a-f0-9]{32}", connection_id) and epoch == value["gateway_epoch"], "connection-binding")
        need(-1 < value["captured_at"] - last_seen <= 45, "worker-heartbeat-stale")
        need(control_id is None, "native-teardown-not-acknowledged")
        need(desktop in {"ready", "locked", "signed_out", "disconnected", "paused", "unavailable"}, "desktop-state")

def compare(before, after):
    idle_gate(before)
    idle_gate(after)
    need(before["gateway_epoch"] != after["gateway_epoch"], "gateway-did-not-restart")
    need(after["captured_at"] >= before["captured_at"] and after["captured_at"] - before["captured_at"] <= 600, "restart-observation-window")
    need(before["active_vm_ids"] == after["active_vm_ids"] and before["vm_identity_sha256"] == after["vm_identity_sha256"], "vm-identity-changed")
    persistent_reauthorized = validate_reauthorization(before, after)
    need(before["job_count"] == after["job_count"] and before["job_records_sha256"] == after["job_records_sha256"], "historical-job-records-changed")
    prior = {row[0]: row[1] for row in before["connections"]}
    need(all(prior[row[0]] != row[1] for row in after["connections"]), "old-worker-connection-reused")
    return {
        "version": 1, "gateway_restart_acceptance": "passed",
        "captured_at": after["captured_at"], "image_id": IMAGE, "container_id": CONTAINER,
        "vm_ids": after["active_vm_ids"], "old_gateway_epoch": before["gateway_epoch"],
        "new_gateway_epoch": after["gateway_epoch"], "vm_identities_unchanged": True,
        "worker_connections_renewed": True, "native_contexts_idle_before_and_after": True,
        "leases_after": len(after['leases']), "reservations_after": 0,
        "persistent_authorizations_preserved": bool(after.get('persistent_authorizations')),
        "persistent_sessions_reauthorized": persistent_reauthorized,
        "lease_invalidation_exercised": any(row[2] == before["gateway_epoch"] and row[3] > before["captured_at"] for row in before["leases"]),
        "active_workflow_invalidation_exercised": False,
        "historical_job_records_unchanged": True,
        "uncertain_desktop_replay_tested": False, "vm_rebooted": False,
        "automatic_boot_recovery_accepted": False, "desktop_acceptance": False,
        "before_sha256": digest(before), "after_sha256": digest(after),
    }

def validate_reauthorization(before, after):
    """Allow only fresh sessions derived from unchanged standing owner consent."""
    present = 'persistent_authorizations' in before or 'persistent_authorizations' in after
    if not present:
        need(after['leases'] == [] and after['reservations'] == [], 'authority-survived-restart')
        return []
    keys = ('persistent_authorizations','lease_bindings','connection_bindings')
    need(all(key in before and key in after for key in keys), 'persistence-evidence-missing')
    need(before['persistent_authorizations'] == after['persistent_authorizations'], 'standing-authorization-changed')
    grants = {row['vm_id']:row for row in after['persistent_authorizations']}
    need(len(grants) == len(after['persistent_authorizations']), 'standing-authorization-binding')
    connections = {row[0]:row for row in after['connection_bindings']}
    need(len(connections) == len(after['connections']), 'session-binding-evidence')
    for vm_id, connection_id, epoch, _seen, _desktop, _control in after['connections']:
        connection = connections.get(vm_id)
        need(connection is not None and len(connection) == 5 and connection[3:] == [connection_id,epoch], 'session-binding-evidence')
    bindings = {row[0]:row for row in after['lease_bindings']}
    need(len(bindings) == len(after['lease_bindings']) == len(after['leases']), 'session-binding-evidence')
    old_leases = {row[1] for row in before['leases']}
    ready = {row[0] for row in after['connections'] if row[4] == 'ready'}
    authorized = []
    for vm_id, lease_id, epoch, expiry in after['leases']:
        grant, binding, connection = grants.get(vm_id), bindings.get(vm_id), connections.get(vm_id)
        need(grant is not None and grant['identity_matches'] is True and grant['paused'] is False
             and re.fullmatch(r'[a-f0-9]{32}',grant['grant_id']), 'standing-authorization-binding')
        need(vm_id in ready and binding is not None and len(binding) == 8 and connection is not None
             and binding[1] == lease_id and binding[3:7] == connection[1:]
             and binding[7] == grant['grant_id'], 'fresh-session-binding')
        issued = binding[2]
        need(lease_id not in old_leases and re.fullmatch(r'[a-f0-9]{32}',lease_id)
             and epoch == after['gateway_epoch'] and type(issued) is int and type(expiry) is int
             and before['captured_at'] <= issued <= after['captured_at'] < expiry
             and 0 < expiry-issued <= MAX_SESSION_LEASE, 'authority-survived-restart')
        authorized.append(vm_id)
    eligible = {vm_id for vm_id,grant in grants.items()
                if vm_id in ready and grant['identity_matches'] is True and grant['paused'] is False}
    need(eligible == set(authorized), 'persistent-reauthorization-missing')
    return authorized

def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ("before", "after"), "fixed-operation")
    path = Path("/state/registry.sqlite3")
    need(path.is_file() and not path.is_symlink(), "registry-path")
    db = sqlite3.connect("file:/state/registry.sqlite3?mode=ro", uri=True, timeout=5)
    try:
        current = snapshot(db)
    finally:
        db.close()
    idle_gate(current)
    if sys.argv[1] == "before":
        result = current
    else:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        need(len(raw) <= MAX_BYTES, "before-bound")
        before = json.loads(raw)
        result = {"acceptance": compare(before, current), "after": current}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z0-9-]{1,80}", str(error)) else "restart-evidence-refused"
        print(json.dumps({"ok": False, "reason": reason}))
        sys.exit(0)
