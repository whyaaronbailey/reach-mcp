"""Durable owner-managed VM registry. Enrollment is never desktop authorization.

Only bearer verifiers and metadata are persisted. Owner operations are deliberately
not exposed on the public OAuth or worker listeners. Use one gateway process; a
new gateway epoch fences old workers, leases and ambiguous jobs.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
import uuid

from channel import ChannelDenied, WorkflowBusy, MAX_LEASE
"""One fixed Nexus registry/administrator admission fence; no authority data."""
from contextlib import contextmanager
import os
import stat
import time
try:
    import fcntl
except ImportError:
    fcntl = None

PATH = '/run/reach-owner-mcp/claim-fence.lock'


@contextmanager
def claim_fence():
    if fcntl is None:
        raise RuntimeError('claim-fence-linux-required')
    parent = os.lstat('/run/reach-owner-mcp')
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 10008
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise RuntimeError('claim-fence-parent')
    fd = os.open(PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 10008
                or stat.S_IMODE(before.st_mode) != 0o640 or before.st_nlink != 1):
            raise RuntimeError('claim-fence-file')
        deadline = time.monotonic() + 2.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('claim-fence-busy') from None
                time.sleep(.002)
        current = os.lstat(PATH)
        if (current.st_dev, current.st_ino, current.st_uid, current.st_gid,
                current.st_mode, current.st_nlink) != (before.st_dev, before.st_ino,
                before.st_uid, before.st_gid, before.st_mode, before.st_nlink):
            raise RuntimeError('claim-fence-replaced')
        yield
    finally:
        os.close(fd)


STATES = frozenset({'ready','locked','signed_out','disconnected','paused','unavailable'})
SESSION_KEYS = frozenset({'version','vm_id','instance_id','session_id','connection_id','gateway_epoch'})
CONNECTION_KEYS = SESSION_KEYS | {'control_id'}
MAX_RESERVATION = 600
HEARTBEAT_TTL = 45
PERSISTENT_CONTEXT_KEYS = frozenset({'policy_sha256','profile_sha256','security_sha256'})


def require(condition):
    if not condition:
        raise ChannelDenied()


def vm_identity(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value))
    return value


def hex_id(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{32}', value))
    return value


def machine_identity(value):
    require(isinstance(value, str))
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise ChannelDenied() from None
    require(value.lower() == normalized and normalized != str(uuid.UUID(int=0)))
    return normalized


def sid_identity(value):
    require(isinstance(value, str) and re.fullmatch(r'S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}', value))
    return value


def subject_identity(value):
    require(isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,19}', value))
    return value


def session_identity(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value))
    return value


def token_digest(authorization):
    require(isinstance(authorization, str) and re.fullmatch(r'Bearer [A-Za-z0-9_-]{43,128}', authorization))
    return hashlib.sha256(authorization[7:].encode('ascii')).hexdigest()


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys) and type(value.get('version')) is int and value['version'] == 2)


def persistent_binding(value):
    """Stable reviewed configuration, deliberately excluding boot/session facts."""
    require(type(value) is dict and set(value) == PERSISTENT_CONTEXT_KEYS)
    require(all(isinstance(item,str) and re.fullmatch(r'[a-f0-9]{64}',item)
                for item in value.values()))
    return json.dumps(value,sort_keys=True,separators=(',',':'))


class Registry:
    def __init__(self, path, clock=time.time, authorization_context=None, *, fence_factory=claim_fence):
        self._claim_fence = fence_factory
        self.clock = clock
        # Only the service/owner console supplies this protected-file reader.
        # A registry without it can inspect or revoke grants, never activate one.
        self.authorization_context = authorization_context
        path = Path(path)
        if str(path) != ':memory:':
            require(path.parent.is_dir() and not path.is_symlink())
        self.db = sqlite3.connect(str(path), timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        with self._claim_fence():
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS vms (
              vm_id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
              machine_uuid TEXT UNIQUE NOT NULL, account_sid TEXT NOT NULL,
              subjects_json TEXT NOT NULL, credential_id TEXT NOT NULL,
              token_hash TEXT NOT NULL, revoked INTEGER NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS grants (
              token_hash TEXT PRIMARY KEY, vm_id TEXT NOT NULL, display_name TEXT NOT NULL,
              machine_uuid TEXT NOT NULL, account_sid TEXT NOT NULL, subjects_json TEXT NOT NULL,
              expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS connections (
              vm_id TEXT PRIMARY KEY REFERENCES vms(vm_id),
              instance_id TEXT NOT NULL, session_id TEXT NOT NULL, connection_id TEXT NOT NULL,
              gateway_epoch TEXT NOT NULL, last_seen REAL NOT NULL, desktop_state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS leases (
              vm_id TEXT PRIMARY KEY REFERENCES vms(vm_id), lease_id TEXT UNIQUE NOT NULL,
              subject TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              instance_id TEXT NOT NULL, session_id TEXT NOT NULL, connection_id TEXT NOT NULL,
              gateway_epoch TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS desktop_authorizations (
              vm_id TEXT PRIMARY KEY REFERENCES vms(vm_id), grant_id TEXT UNIQUE NOT NULL,
              subject TEXT NOT NULL, machine_uuid TEXT NOT NULL, account_sid TEXT NOT NULL,
              context_json TEXT NOT NULL, paused INTEGER NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (
              job_id TEXT PRIMARY KEY, vm_id TEXT NOT NULL, lease_id TEXT NOT NULL,
              gateway_epoch TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL,
              deadline INTEGER NOT NULL, tool TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY, time INTEGER NOT NULL, event TEXT NOT NULL,
              vm_id TEXT, reference TEXT);
            """)
            # Existing registries migrate without replaying old jobs or retaining authority.
            for table, column in (('connections','control_id'),('jobs','control_id')):
                if column not in {row['name'] for row in self.db.execute('PRAGMA table_info('+table+')')}:
                    self.db.execute('ALTER TABLE '+table+' ADD COLUMN '+column+' TEXT')
            self.db.execute("""CREATE TABLE IF NOT EXISTS reservations (
              vm_id TEXT PRIMARY KEY REFERENCES vms(vm_id), control_id TEXT UNIQUE NOT NULL,
              token_hash TEXT NOT NULL, subject TEXT NOT NULL, lease_id TEXT NOT NULL,
              gateway_epoch TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS admin_end_outbox (
              scope TEXT PRIMARY KEY, binding_json TEXT NOT NULL, created_at REAL NOT NULL)""")
            require(self.db.execute("PRAGMA integrity_check").fetchone()[0] == 'ok')

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        with self._claim_fence():
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            else:
                self.db.execute('COMMIT')

    def audit(self, event, vm_id=None, reference=None):
        self.db.execute('INSERT INTO audit(time,event,vm_id,reference) VALUES(?,?,?,?)',
                        (int(self.clock()), event, vm_id, reference))

    def get(self, vm_id):
        """Internal row, including credential verifier; do not serialize to callers."""
        row = self.db.execute('SELECT * FROM vms WHERE vm_id=?', (vm_identity(vm_id),)).fetchone()
        require(row is not None)
        return row

    def epoch(self):
        row = self.db.execute("SELECT value FROM settings WHERE key='gateway_epoch'").fetchone()
        require(row is not None)
        return row[0]

    def assert_epoch(self, epoch):
        require(hmac.compare_digest(self.epoch(), epoch))

    def start_gateway(self):
        epoch = secrets.token_hex(16)
        with self.transaction():
            self.db.execute("INSERT OR REPLACE INTO settings VALUES('gateway_epoch',?)", (epoch,))
            self.db.execute("UPDATE jobs SET state=CASE state WHEN 'delivered' THEN 'outcome_uncertain' ELSE 'discarded' END WHERE state IN ('queued','delivered')")
            for reservation in self.db.execute('SELECT * FROM reservations').fetchall():
                self._queue_admin_end(reservation)
            self.db.execute('DELETE FROM reservations')
            self.db.execute('DELETE FROM connections')
            self.db.execute('DELETE FROM leases')
            self.audit('gateway_started', reference=epoch)
        return epoch

    def grant(self, vm_id, display_name, machine_uuid, account_sid, allowed_subjects, ttl=600):
        vm_id, machine_uuid, account_sid = vm_identity(vm_id), machine_identity(machine_uuid), sid_identity(account_sid)
        require(isinstance(display_name, str) and 1 <= len(display_name) <= 80 and all(ord(c) >= 32 for c in display_name))
        require(type(allowed_subjects) is list and 1 <= len(allowed_subjects) <= 16)
        subjects = sorted(set(subject_identity(s) for s in allowed_subjects))
        require(type(ttl) is int and 1 <= ttl <= 900)
        token, expires = secrets.token_urlsafe(32), int(self.clock()) + ttl
        digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        with self.transaction():
            prior = self.db.execute('SELECT * FROM vms WHERE vm_id=? OR machine_uuid=?', (vm_id, machine_uuid)).fetchall()
            for row in prior:
                require(row['vm_id'] == vm_id and row['machine_uuid'] == machine_uuid and row['account_sid'] == account_sid)
            # Issuing a new grant invalidates older unconsumed grants for this VM.
            self.db.execute('UPDATE grants SET consumed=1 WHERE vm_id=?', (vm_id,))
            self.db.execute('INSERT INTO grants VALUES(?,?,?,?,?,?,?,0)',
                            (digest, vm_id, display_name, machine_uuid, account_sid, json.dumps(subjects), expires))
            self.audit('enrollment_granted', vm_id)
        return {'version':2,'vm_id':vm_id,'enrollment_token':token,'expires_at':expires}

    def enroll(self, authorization, value):
        exact(value, {'version','vm_id','machine_uuid','account_sid'})
        vm_id = vm_identity(value['vm_id'])
        machine_uuid, account_sid = machine_identity(value['machine_uuid']), sid_identity(value['account_sid'])
        digest = token_digest(authorization)
        token, credential_id = secrets.token_urlsafe(32), secrets.token_hex(16)
        with self.transaction():
            grant = self.db.execute('SELECT * FROM grants WHERE token_hash=?', (digest,)).fetchone()
            require(grant is not None and not grant['consumed'] and self.clock() < grant['expires_at'])
            require((grant['vm_id'],grant['machine_uuid'],grant['account_sid']) == (vm_id,machine_uuid,account_sid))
            existing = self.db.execute('SELECT * FROM vms WHERE vm_id=? OR machine_uuid=?', (vm_id,machine_uuid)).fetchall()
            for row in existing:
                require((row['vm_id'],row['machine_uuid'],row['account_sid']) == (vm_id,machine_uuid,account_sid))
            self.db.execute('UPDATE grants SET consumed=1 WHERE token_hash=?', (digest,))
            self.db.execute("""INSERT INTO vms VALUES(?,?,?,?,?,?,?,0,?)
              ON CONFLICT(vm_id) DO UPDATE SET display_name=excluded.display_name,
              subjects_json=excluded.subjects_json,credential_id=excluded.credential_id,
              token_hash=excluded.token_hash,revoked=0""",
              (vm_id,grant['display_name'],machine_uuid,account_sid,grant['subjects_json'],
               credential_id,hashlib.sha256(token.encode('ascii')).hexdigest(),int(self.clock())))
            self._drop_reservation(vm_id)
            self.db.execute('DELETE FROM desktop_authorizations WHERE vm_id=?', (vm_id,))
            self.db.execute('DELETE FROM leases WHERE vm_id=?', (vm_id,))
            self.db.execute('DELETE FROM connections WHERE vm_id=?', (vm_id,))
            self.audit('enrolled', vm_id, credential_id)
        return {'version':2,'vm_id':vm_id,'worker_token':token,'credential_id':credential_id}

    def authenticate(self, authorization, vm_id):
        digest = token_digest(authorization)
        row = self.get(vm_id)
        require(not row['revoked'] and hmac.compare_digest(row['token_hash'], digest))
        return row

    def allowed(self, vm_id, subject):
        subject_identity(subject)
        row = self.get(vm_id)
        require(subject in json.loads(row['subjects_json']))
        return row

    def _binding(self, value, connection):
        require(connection is not None)
        for key in SESSION_KEYS - {'version','vm_id'}:
            require(isinstance(value.get(key),str) and hmac.compare_digest(value[key], connection[key]))
        require(value['vm_id'] == connection['vm_id'])
        self.assert_epoch(value['gateway_epoch'])

    def connect(self, authorization, value, epoch):
        exact(value, {'version','vm_id','machine_uuid','account_sid','instance_id','session_id','desktop_state','control_id','control_protocol'})
        require(value['control_id'] is None and type(value['control_protocol']) is int and value['control_protocol']==1)
        hex_id(value['instance_id'])
        session_identity(value['session_id'])
        require(value['desktop_state'] in STATES)
        with self.transaction():
            self.assert_epoch(epoch)
            vm = self.authenticate(authorization, value['vm_id'])
            require(vm['machine_uuid'] == machine_identity(value['machine_uuid']) and vm['account_sid'] == sid_identity(value['account_sid']))
            old = self.db.execute('SELECT * FROM connections WHERE vm_id=?', (vm['vm_id'],)).fetchone()
            if old:
                self._active_reservation(vm['vm_id'])  # expire before reconnect refreshes liveness
            same = old and (old['instance_id'],old['session_id'],old['gateway_epoch']) == (value['instance_id'],value['session_id'],epoch)
            require(not old or same or self.clock() - old['last_seen'] > HEARTBEAT_TTL)
            connection_id = old['connection_id'] if same else secrets.token_hex(16)
            if not same or value['desktop_state'] != 'ready':
                self._drop_reservation(vm['vm_id'])
                self.db.execute('DELETE FROM leases WHERE vm_id=?', (vm['vm_id'],))
            elif old['control_id'] is not None:
                # Reconnecting after a native context existed cannot resume its handles.
                self._drop_reservation(vm['vm_id'])
            self.db.execute('INSERT OR REPLACE INTO connections VALUES(?,?,?,?,?,?,?,NULL)',
                (vm['vm_id'],value['instance_id'],value['session_id'],connection_id,epoch,self.clock(),value['desktop_state']))
            if not same:
                self.audit('worker_connected', vm['vm_id'], connection_id)
            self._refresh_persistent_lease(vm['vm_id'])
        return {'version':2,'vm_id':vm['vm_id'],'connection_id':connection_id,'gateway_epoch':epoch,
                'lease':self.lease_public(vm['vm_id']),'control':self.control_public(vm['vm_id'])}

    def connection(self, authorization, value, heartbeat=False):
        exact(value, CONNECTION_KEYS | ({'desktop_state'} if heartbeat else set()))
        hex_id(value['instance_id']);hex_id(value['connection_id']);hex_id(value['gateway_epoch'])
        session_identity(value['session_id'])
        require(value['control_id'] is None or hex_id(value['control_id']))
        if heartbeat:
            require(value['desktop_state'] in STATES)
        with self.transaction():
            self.authenticate(authorization, value['vm_id'])
            row = self.db.execute('SELECT * FROM connections WHERE vm_id=?', (value['vm_id'],)).fetchone()
            self._binding(value, row)
            require(self.clock() - row['last_seen'] <= HEARTBEAT_TTL)
            if heartbeat:
                if value['desktop_state'] != 'ready':
                    self._drop_reservation(value['vm_id'])
                    self.db.execute('DELETE FROM leases WHERE vm_id=?', (value['vm_id'],))
                desired = self.control_public(value['vm_id'])
                target = desired['control_id'] if desired else None
                # Old ack may fetch a changed target; only the current target can be newly acknowledged.
                require(value['control_id'] in (row['control_id'],target))
                self.db.execute('UPDATE connections SET last_seen=?,desktop_state=?,control_id=? WHERE vm_id=?',
                                (self.clock(),value['desktop_state'],value['control_id'],value['vm_id']))
                self._refresh_persistent_lease(value['vm_id'])
            else:
                require(value['control_id'] == row['control_id'])
        return self.db.execute('SELECT * FROM connections WHERE vm_id=?', (value['vm_id'],)).fetchone()

    def owner_connection(self, vm_id):
        vm = self.get(vm_id)
        row = self.db.execute('SELECT * FROM connections WHERE vm_id=?',(vm_id,)).fetchone()
        if row is None:
            return None
        return {**dict(row), 'machine_uuid': vm['machine_uuid'], 'account_sid': vm['account_sid']}

    def _persistent_valid(self, grant, vm):
        if (grant['paused'] or vm['revoked'] or self.authorization_context is None
                or (grant['machine_uuid'],grant['account_sid']) != (vm['machine_uuid'],vm['account_sid'])
                or grant['subject'] not in json.loads(vm['subjects_json'])):
            return False
        try:
            current = persistent_binding(self.authorization_context(vm['vm_id']))
            return hmac.compare_digest(current,grant['context_json'])
        except (ChannelDenied,OSError,ValueError,TypeError,KeyError):
            # Missing/changed protected inputs never fall back to enrollment.
            return False

    def _refresh_persistent_lease(self, vm_id):
        """Materialize standing owner consent into this exact live session.

        Authorization has no expiry. Worker leases remain bounded, and renewing
        a live lease keeps its generation so a workflow can finish normally.
        Expired/session/epoch generations are never resurrected.
        """
        if not self.db.in_transaction:
            with self.transaction():
                return self._refresh_persistent_lease(vm_id)
        grant = self.db.execute('SELECT * FROM desktop_authorizations WHERE vm_id=?',(vm_id,)).fetchone()
        if grant is None:
            return
        vm = self.get(vm_id)
        connection = self.db.execute('SELECT * FROM connections WHERE vm_id=?',(vm_id,)).fetchone()
        if (not self._persistent_valid(grant,vm) or connection is None
                or connection['desktop_state'] != 'ready'
                or not 0 <= self.clock()-connection['last_seen'] <= HEARTBEAT_TTL
                or connection['gateway_epoch'] != self.epoch()):
            self._drop_reservation(vm_id)
            self.db.execute('DELETE FROM leases WHERE vm_id=?',(vm_id,))
            return
        lease = self.db.execute('SELECT * FROM leases WHERE vm_id=?',(vm_id,)).fetchone()
        now = int(self.clock())
        same = (lease is not None and lease['subject']==grant['subject']
                and self.clock()<lease['expires_at'] and all(lease[key]==connection[key]
                    for key in SESSION_KEYS-{'version','vm_id'}))
        if same:
            # Renew well before an ordinary workflow can hit the internal bound.
            if lease['expires_at']-now <= MAX_RESERVATION+HEARTBEAT_TTL:
                self.db.execute('UPDATE leases SET issued_at=?,expires_at=? WHERE vm_id=?',
                                (now,now+MAX_LEASE,vm_id))
                self.audit('persistent_session_renewed',vm_id,lease['lease_id'])
            return
        self._drop_reservation(vm_id)
        lease_id = secrets.token_hex(16)
        self.db.execute('INSERT OR REPLACE INTO leases VALUES(?,?,?,?,?,?,?,?,?)',
            (vm_id,lease_id,grant['subject'],now,now+MAX_LEASE,connection['instance_id'],
             connection['session_id'],connection['connection_id'],connection['gateway_epoch']))
        self.audit('persistent_session_authorized',vm_id,lease_id)

    def authorize_persistent(self, vm_id, subject, binding, expected_connection):
        """Owner-only standing grant, after fresh boundary proof verification."""
        binding_json = persistent_binding(binding)
        with self.transaction():
            vm = self.allowed(vm_id,subject)
            require(not vm['revoked'] and self.authorization_context is not None)
            require(hmac.compare_digest(binding_json,persistent_binding(self.authorization_context(vm_id))))
            connection = self.db.execute('SELECT * FROM connections WHERE vm_id=?',(vm_id,)).fetchone()
            require(connection is not None and connection['desktop_state']=='ready'
                    and 0 <= self.clock()-connection['last_seen'] <= HEARTBEAT_TTL)
            self.assert_epoch(connection['gateway_epoch'])
            require(type(expected_connection) is dict and set(expected_connection)=={'connection_id','gateway_epoch'})
            require(all(expected_connection[key]==connection[key] for key in expected_connection))
            self._drop_reservation(vm_id)
            self.db.execute('DELETE FROM leases WHERE vm_id=?',(vm_id,))
            grant_id = secrets.token_hex(16)
            self.db.execute('INSERT OR REPLACE INTO desktop_authorizations VALUES(?,?,?,?,?,?,0,?)',
                (vm_id,grant_id,subject,vm['machine_uuid'],vm['account_sid'],binding_json,int(self.clock())))
            self.audit('persistent_authorization_granted',vm_id,grant_id)
            self._refresh_persistent_lease(vm_id)
        return {'vm_id':vm_id,'persistent':True,'expires_at':None,'paused':False}

    def revoke_persistent(self, vm_id):
        with self.transaction():
            self.get(vm_id)
            self.db.execute('DELETE FROM desktop_authorizations WHERE vm_id=?',(vm_id,))
            self._drop_reservation(vm_id)
            self.db.execute('DELETE FROM leases WHERE vm_id=?',(vm_id,))
            self.audit('persistent_authorization_revoked',vm_id)
        return {'vm_id':vm_id,'persistent':False,'revoked':True}

    def authorize_lease(self, vm_id, subject, seconds=MAX_LEASE, expected_connection=None):
        require(type(seconds) is int and 1 <= seconds <= MAX_LEASE)
        with self.transaction():
            vm = self.allowed(vm_id, subject)
            require(not vm['revoked'])
            # Do not let an old renewal helper silently downgrade standing
            # consent or undo its pause. Owner must explicitly revoke/regrant.
            require(self.db.execute('SELECT 1 FROM desktop_authorizations WHERE vm_id=?',
                                    (vm_id,)).fetchone() is None)
            connection = self.db.execute('SELECT * FROM connections WHERE vm_id=?', (vm_id,)).fetchone()
            require(connection is not None and connection['desktop_state'] == 'ready'
                    and self.clock() - connection['last_seen'] <= HEARTBEAT_TTL)
            self.assert_epoch(connection['gateway_epoch'])
            if expected_connection is not None:
                require(type(expected_connection) is dict and set(expected_connection)=={'connection_id','gateway_epoch'})
                require(all(expected_connection[key]==connection[key] for key in expected_connection))
            self._drop_reservation(vm_id)
            now, lease_id = int(self.clock()), secrets.token_hex(16)
            self.db.execute('INSERT OR REPLACE INTO leases VALUES(?,?,?,?,?,?,?,?,?)',
                (vm_id,lease_id,subject,now,now+seconds,connection['instance_id'],connection['session_id'],
                 connection['connection_id'],connection['gateway_epoch']))
            self.audit('lease_authorized', vm_id, lease_id)
        return self.lease_public(vm_id)

    def lease_public(self, vm_id):
        self._refresh_persistent_lease(vm_id)
        row = self.db.execute('SELECT * FROM leases WHERE vm_id=?', (vm_id,)).fetchone()
        if row is None or self.clock() >= row['expires_at']:
            return None
        return {**dict(row),'approval_policy':'client'}

    def authorize(self, vm_id, subject, epoch, lease_id=None):
        vm = self.allowed(vm_id, subject)
        require(not vm['revoked'])
        self.assert_epoch(epoch)
        self._refresh_persistent_lease(vm_id)
        lease = self.db.execute('SELECT * FROM leases WHERE vm_id=?', (vm_id,)).fetchone()
        require(lease is not None and lease['subject'] == subject and self.clock() < lease['expires_at'])
        require(lease_id is None or lease_id == lease['lease_id'])
        connection = self.db.execute('SELECT * FROM connections WHERE vm_id=?', (vm_id,)).fetchone()
        require(connection is not None and connection['desktop_state'] == 'ready'
                and self.clock() - connection['last_seen'] <= HEARTBEAT_TTL)
        self._binding({'version':2,**dict(lease)}, connection)
        return dict(lease)


    def _queue_admin_end(self, row):
        require(self.db.in_transaction)
        keys = ('subject', 'vm_id', 'control_id', 'lease_id', 'gateway_epoch')
        binding = {key: row[key] for key in keys}
        binding['expires_at'] = row['expires_at']
        scope = hashlib.sha256(json.dumps([binding[k] for k in keys],
            separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
        self.db.execute('INSERT OR IGNORE INTO admin_end_outbox VALUES(?,?,?)',
            (scope, json.dumps(binding, sort_keys=True, separators=(',', ':')), self.clock()))

    def admin_end_events(self, limit=32):
        require(type(limit) is int and 1 <= limit <= 32)
        return [dict(r) for r in self.db.execute(
            'SELECT scope,binding_json FROM admin_end_outbox ORDER BY created_at,scope LIMIT ?', (limit,))]

    def acknowledge_admin_end(self, scope, binding_json):
        # Reduction delivery acknowledgement only; never changes owner authority.
        with self.transaction():
            self.db.execute('DELETE FROM admin_end_outbox WHERE scope=? AND binding_json=?',
                (scope, binding_json))

    def _drop_reservation(self, vm_id, expected_control_id=None, expected_expires_at=None):
        if not self.db.in_transaction:
            with self.transaction():
                return self._drop_reservation(vm_id,expected_control_id,expected_expires_at)
        row = self.db.execute('SELECT * FROM reservations WHERE vm_id=?',(vm_id,)).fetchone()
        if (row and (expected_control_id is None or row['control_id']==expected_control_id)
                and (expected_expires_at is None or row['expires_at']==expected_expires_at)):
            # Delete the exact observed version first. A concurrent same-generation
            # renewal must not lose its reservation or have its jobs marked uncertain.
            deleted=self.db.execute('DELETE FROM reservations WHERE vm_id=? AND control_id=? AND expires_at=?',
                                    (vm_id,row['control_id'],row['expires_at']))
            if deleted.rowcount:
                self._queue_admin_end(row)
                self.db.execute("UPDATE jobs SET state=CASE state WHEN 'delivered' THEN 'outcome_uncertain' ELSE 'discarded' END WHERE vm_id=? AND control_id=? AND state IN ('queued','delivered')",(vm_id,row['control_id']))
                self.audit('control_ended',vm_id,row['control_id'])

    def _active_reservation(self, vm_id):
        row = self.db.execute('SELECT * FROM reservations WHERE vm_id=?',(vm_id,)).fetchone()
        if row:
            try:
                self.authorize(vm_id,row['subject'],row['gateway_epoch'],row['lease_id'])
                require(self.clock() < row['expires_at'])
            except ChannelDenied:
                # Expiry may race an owner renewal on another SQLite connection.
                # Never clear a successor generation observed after this stale read.
                self._drop_reservation(vm_id,row['control_id'],row['expires_at'])
                return None
        return row

    def control_public(self, vm_id):
        """Authenticated worker target; never contains a workflow capability."""
        row = self._active_reservation(vm_id)
        return {key:row[key] for key in ('control_id','lease_id','expires_at')} if row else None

    def reservation_status(self, vm_id, subject):
        self.allowed(vm_id,subject)
        row = self._active_reservation(vm_id)
        connection = self.db.execute('SELECT * FROM connections WHERE vm_id=?',(vm_id,)).fetchone()
        if row:
            phase = 'ready' if connection and connection['control_id']==row['control_id'] else 'preparing'
        else:
            phase = 'draining' if connection and connection['control_id'] is not None else 'idle'
        return {'phase':phase,'reserved':bool(row),'expires_at':row['expires_at'] if row else None}

    def claim(self, vm_id, subject, seconds=MAX_RESERVATION):
        require(type(seconds) is int and 1 <= seconds <= MAX_RESERVATION)
        with self.transaction():
            lease = self.authorize(vm_id,subject,self.epoch())
            row = self._active_reservation(vm_id)
            connection = self.db.execute('SELECT * FROM connections WHERE vm_id=?',(vm_id,)).fetchone()
            if row or connection['control_id'] is not None:
                return {'vm_id':vm_id,'claimed':False,**self.reservation_status(vm_id,subject)}
            token, control_id = secrets.token_urlsafe(32), secrets.token_hex(16)
            expires = min(int(self.clock())+seconds,lease['expires_at'])
            self.db.execute('INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)',
                (vm_id,control_id,hashlib.sha256(token.encode('ascii')).hexdigest(),subject,lease['lease_id'],
                 lease['gateway_epoch'],int(self.clock()),expires))
            self.audit('control_claimed',vm_id,control_id)
            return {'vm_id':vm_id,'claimed':True,'workflow_token':token,
                    **self.reservation_status(vm_id,subject)}

    def _reservation_token(self, vm_id, subject, workflow_token):
        self.allowed(vm_id,subject)
        digest = token_digest('Bearer '+workflow_token if isinstance(workflow_token,str) else None)
        row = self._active_reservation(vm_id)
        require(row is not None and row['subject']==subject and hmac.compare_digest(row['token_hash'],digest))
        return row

    def renew_claim(self, vm_id, subject, workflow_token, seconds=MAX_RESERVATION):
        require(type(seconds) is int and 1 <= seconds <= MAX_RESERVATION)
        with self.transaction():
            row = self._reservation_token(vm_id,subject,workflow_token)
            lease = self.authorize(vm_id,subject,row['gateway_epoch'],row['lease_id'])
            expires = min(int(self.clock())+seconds,lease['expires_at'])
            self.db.execute('UPDATE reservations SET expires_at=? WHERE vm_id=?',(expires,vm_id))
            self.audit('control_renewed',vm_id,row['control_id'])
            return {'vm_id':vm_id,'renewed':True,**self.reservation_status(vm_id,subject)}

    def release_claim(self, vm_id, subject, workflow_token):
        with self.transaction():
            self._reservation_token(vm_id,subject,workflow_token)
            self._drop_reservation(vm_id)
            return {'vm_id':vm_id,'released':True,**self.reservation_status(vm_id,subject)}

    def authorize_control(self, vm_id, subject, epoch, control_id, ready=True):
        """Internal fence. Public callers must additionally prove their capability."""
        self.assert_epoch(epoch)
        row = self._active_reservation(vm_id)
        require(row is not None and row['subject']==subject and row['control_id']==hex_id(control_id))
        lease = self.authorize(vm_id,subject,epoch,row['lease_id'])
        connection = self.db.execute('SELECT control_id FROM connections WHERE vm_id=?',(vm_id,)).fetchone()
        if ready and connection['control_id']!=control_id:
            raise WorkflowBusy()
        return lease,dict(row)

    def authorize_reservation(self, vm_id, subject, epoch, workflow_token, ready=True):
        row = self._reservation_token(vm_id,subject,workflow_token)
        return self.authorize_control(vm_id,subject,epoch,row['control_id'],ready=ready)

    def abandon_control(self, vm_id, control_id):
        # A canceled/delivered-uncertain call closes its entire native context.
        with self.transaction():
            row = self.db.execute('SELECT control_id FROM reservations WHERE vm_id=?',(vm_id,)).fetchone()
            if row and row['control_id']==control_id:
                self._drop_reservation(vm_id)

    def pause(self, vm_id):
        self.get(vm_id)
        with self.transaction():
            self.db.execute('UPDATE desktop_authorizations SET paused=1 WHERE vm_id=?',(vm_id,))
            self._drop_reservation(vm_id)
            self.db.execute('DELETE FROM leases WHERE vm_id=?', (vm_id,))
            self.audit('lease_revoked', vm_id)
        return {'vm_id':vm_id,'paused':True}

    def _revoke_locked(self, vm_id):
        self.db.execute('UPDATE vms SET revoked=1 WHERE vm_id=?', (vm_id,))
        self.db.execute('UPDATE grants SET consumed=1 WHERE vm_id=?', (vm_id,))
        self.db.execute('DELETE FROM desktop_authorizations WHERE vm_id=?',(vm_id,))
        self._drop_reservation(vm_id)
        self.db.execute('DELETE FROM leases WHERE vm_id=?', (vm_id,))
        self.db.execute('DELETE FROM connections WHERE vm_id=?', (vm_id,))
        self.audit('vm_revoked', vm_id)

    def revoke(self, vm_id):
        with self.transaction():
            self.get(vm_id)
            self._revoke_locked(vm_id)
        return {'vm_id':vm_id,'revoked':True}

    def self_revoke(self, authorization, value):
        exact(value, {'version','vm_id'})
        digest = token_digest(authorization)
        # This single endpoint may confirm a prior revocation with the CURRENT
        # exact credential. It never restores authentication or desktop authority.
        # Check and revoke in one transaction so a rotated credential cannot race.
        with self.transaction():
            row = self.get(value['vm_id'])
            require(hmac.compare_digest(row['token_hash'], digest))
            if not row['revoked']:
                self._revoke_locked(row['vm_id'])
        return {'vm_id':value['vm_id'],'revoked':True}

    def list_vms(self, subject=None):
        if subject is not None:
            subject_identity(subject)
        result = []
        for vm in self.db.execute('SELECT * FROM vms ORDER BY vm_id'):
            if subject is not None and subject not in json.loads(vm['subjects_json']):
                continue
            connection = self.db.execute('SELECT * FROM connections WHERE vm_id=?', (vm['vm_id'],)).fetchone()
            lease = self.lease_public(vm['vm_id'])
            persistent = self.db.execute('SELECT * FROM desktop_authorizations WHERE vm_id=?',(vm['vm_id'],)).fetchone()
            if persistent and subject is not None and persistent['subject']!=subject:
                persistent = None
            online = bool(connection and self.clock()-connection['last_seen'] <= HEARTBEAT_TTL)
            state = 'revoked' if vm['revoked'] else (connection['desktop_state'] if online else 'offline')
            result.append({'vm_id':vm['vm_id'],'display_name':vm['display_name'],'platform':'windows',
                'enrolled':not bool(vm['revoked']),'connection_state':'online' if online and not vm['revoked'] else 'offline',
                'desktop_state':state,'desktop_authorized':bool(lease and online and state=='ready' and (subject is None or lease['subject']==subject)),
                'lease_expires_at':lease['expires_at'] if lease else None,
                'desktop_authorization':({'mode':'persistent','persistent':True,'expires_at':None,
                    'paused':bool(persistent['paused'])} if persistent else
                    {'mode':'temporary' if lease else 'none','persistent':False,
                     'expires_at':lease['expires_at'] if lease else None}),
                'last_seen':connection['last_seen'] if connection else None,
                'reservation':self.reservation_status(vm['vm_id'],subject) if subject is not None else None})
        return result

    def create_job(self, packet, tool):
        with self.transaction():
            self.assert_epoch(packet['gateway_epoch'])
            self.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)',
                (packet['job_id'],packet['vm_id'],packet['lease_id'],packet['gateway_epoch'],'queued',
                 int(self.clock()),packet['deadline'],tool,packet['control_id']))
            self.audit('job_queued',packet['vm_id'],packet['job_id'])

    def deliver_job(self, packet):
        with self.transaction():
            self.assert_epoch(packet['gateway_epoch'])
            cursor=self.db.execute("UPDATE jobs SET state='delivered' WHERE job_id=? AND vm_id=? AND lease_id=? AND gateway_epoch=? AND control_id=? AND state='queued'",
                (packet['job_id'],packet['vm_id'],packet['lease_id'],packet['gateway_epoch'],packet['control_id']))
            require(cursor.rowcount == 1)
            self.audit('job_delivered',packet['vm_id'],packet['job_id'])

    def finish_job(self, job_id, state):
        require(state in {'completed','failed','discarded','outcome_uncertain'})
        with self.transaction():
            row=self.db.execute('SELECT * FROM jobs WHERE job_id=?',(job_id,)).fetchone()
            require(row is not None)
            if row['state'] in {'queued','delivered'}:
                self.db.execute('UPDATE jobs SET state=? WHERE job_id=?',(state,job_id))
                self.audit('job_'+state,row['vm_id'],job_id)
