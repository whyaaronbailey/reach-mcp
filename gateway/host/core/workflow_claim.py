"""Pinned RO predicate embedded by the Root guard inside the current gateway.

No database creation/migration, mutation, lease refresh, file write, network or
approval. `context` is the actual pinned admin.persistent_context callable.
"""
import hashlib
import json
import math
import re
import time

IDENTITY = ('subject', 'vm_id', 'control_id', 'lease_id', 'gateway_epoch')


class ClaimRefused(RuntimeError):
    pass


def need(value, reason):
    if not value:
        raise ClaimRefused(reason)


def scope(binding):
    return hashlib.sha256(json.dumps([binding[k] for k in IDENTITY],
        separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()


def row(db, sql, args=()):
    cursor = db.execute(sql, args)
    value = cursor.fetchone()
    return None if value is None else dict(zip((v[0] for v in cursor.description), value))


def verify(db, binding, actual_context, wall=time.time):
    need(type(binding) is dict and set(binding) == set(IDENTITY) | {'expires_at'}, 'binding-fields')
    need(binding['vm_id'] in ('vm-alpha', 'vm-beta', 'vm-gamma') and type(binding['subject']) is str
         and re.fullmatch('[1-9][0-9]{0,19}', binding['subject']), 'binding-owner')
    for key in ('control_id', 'lease_id', 'gateway_epoch'):
        need(type(binding[key]) is str and re.fullmatch('[a-f0-9]{32}', binding[key]), 'binding-id')
    now = wall()
    need(type(now) in (int, float) and math.isfinite(now), 'clock')
    vm_id = binding['vm_id']
    epoch = row(db, "SELECT value FROM settings WHERE key='gateway_epoch'")
    need(epoch == {'value': binding['gateway_epoch']}, 'gateway-epoch')
    vm = row(db, 'SELECT * FROM vms WHERE vm_id=?', (vm_id,))
    need(vm is not None and vm['revoked'] == 0, 'vm-revoked')
    try:
        members = json.loads(vm['subjects_json'])
    except (ValueError, TypeError):
        raise ClaimRefused('owner-membership') from None
    need(type(members) is list and all(type(v) is str for v in members)
         and binding['subject'] in members, 'owner-membership')
    reservation = row(db, 'SELECT * FROM reservations WHERE vm_id=?', (vm_id,))
    lease = row(db, 'SELECT * FROM leases WHERE vm_id=?', (vm_id,))
    connection = row(db, 'SELECT * FROM connections WHERE vm_id=?', (vm_id,))
    need(reservation is not None and lease is not None and connection is not None, 'live-claim-required')
    for key in IDENTITY:
        need(reservation[key] == binding[key], 'reservation-generation')
    for key in ('subject', 'vm_id', 'lease_id', 'gateway_epoch'):
        need(lease[key] == binding[key], 'lease-generation')
    need(connection['vm_id'] == vm_id and connection['control_id'] == binding['control_id']
         and connection['desktop_state'] == 'ready', 'connection-control')
    for key in ('instance_id', 'session_id', 'connection_id', 'gateway_epoch'):
        need(lease[key] == connection[key], 'lease-connection')
    need(type(connection['last_seen']) in (int, float) and math.isfinite(connection['last_seen'])
         and 0 <= now - connection['last_seen'] <= 45, 'connection-heartbeat')
    for value in (reservation['expires_at'], lease['expires_at']):
        need(type(value) in (int, float) and math.isfinite(value) and value > now, 'claim-expired')
    expires = min(reservation['expires_at'], lease['expires_at'])
    need(reservation['expires_at'] <= now + 600, 'reservation-expiry-bound')
    grant = row(db, 'SELECT * FROM desktop_authorizations WHERE vm_id=?', (vm_id,))
    anchor = {'machine_uuid': vm['machine_uuid'], 'account_sid': vm['account_sid'],
              'instance_id': lease['instance_id'], 'session_id': lease['session_id'],
              'connection_id': lease['connection_id'], 'standing_grant': None}
    if grant is not None:
        need(grant['paused'] == 0 and grant['subject'] == binding['subject']
             and (grant['machine_uuid'], grant['account_sid']) ==
                 (vm['machine_uuid'], vm['account_sid']), 'standing-grant-paused-or-changed')
        value = actual_context(vm_id)
        need(type(value) is dict and set(value) == {'policy_sha256', 'profile_sha256', 'security_sha256'}
             and all(type(v) is str and re.fullmatch('[a-f0-9]{64}', v) for v in value.values()),
             'actual-context-fields')
        canonical = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        need(canonical == grant['context_json'], 'actual-context-changed')
        anchor['standing_grant'] = {k: grant[k] for k in
            ('grant_id', 'subject', 'machine_uuid', 'account_sid', 'context_json', 'paused', 'created_at')}
    # Context reads may take time: expiry is checked again by the Root guard at
    # transport admission too. This second check also protects the prepare path.
    need(wall() < expires, 'claim-expired-during-context-read')
    return {'binding': {**{k: reservation[k] for k in IDENTITY}, 'expires_at': expires},
            'scope': scope(binding), 'anchor': anchor, 'lease_expires_at': lease['expires_at'],
            'reservation_expires_at': reservation['expires_at']}
