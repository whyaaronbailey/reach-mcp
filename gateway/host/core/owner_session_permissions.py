"""Permission ledger for the trusted local owner executor, never a public tool.

The protected caller verifies native lifecycle events and actual human approval.
An approval reference is an audit pointer, not proof of consent. This module
does not accept an ``approved`` boolean, execute a command, infer chat identity,
or claim that every chat provider exposes a trustworthy session-end event.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time


class PermissionDenied(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise PermissionDenied(reason)


def identifier(value, name='identifier'):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}',value),
         'invalid-'+name)
    return value


def reference(value):
    need(type(value) is str and 1<=len(value.encode('utf-8'))<=1024
         and all(ord(char)>=32 and ord(char)!=127 for char in value), 'invalid-approval-reference')
    return value


def generation_id(value):
    need(type(value) is str and re.fullmatch(r'[a-f0-9]{32}',value), 'invalid-generation')
    return value


def request_hash(value):
    need(type(value) is str and re.fullmatch(r'[a-f0-9]{64}',value), 'invalid-request-hash')
    return value


def vm_identity(value):
    need(value in ('vm-alpha','vm-beta','vm-gamma'), 'invalid-vm-id')
    return value


def vm_scope(value):
    value = ['vm-alpha','vm-beta','vm-gamma'] if value is None else value
    need(type(value) is list and 1<=len(value)<=3, 'invalid-vm-scope')
    need(all(type(item) is str for item in value), 'invalid-vm-scope')
    return sorted(set(vm_identity(item) for item in value))


class OwnerSessionPermissions:
    """Session-fenced ask-each/session consent with one dispatch per operation ID.

    The caller provisions a protected parent directory and checks its platform
    ownership/ACLs. No credentials, command text or approval-message text belong
    in this ledger. Multiple native session IDs remain independent.
    """
    def __init__(self, path, clock=time.time):
        self.clock = clock
        path = Path(path)
        if str(path)!=':memory:':
            need(path.parent.is_dir() and not path.is_symlink(), 'protected-ledger-path-required')
            if not path.exists():
                fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                os.close(fd)
            need(path.is_file(), 'protected-ledger-path-required')
        self.db = sqlite3.connect(str(path),timeout=5,isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS owner_sessions (
          generation TEXT PRIMARY KEY, session_id TEXT NOT NULL,
          lifecycle_reference TEXT NOT NULL, started_at INTEGER NOT NULL,
          ended_at INTEGER, end_reference TEXT, mode TEXT NOT NULL,
          approval_reference TEXT, permission_revision INTEGER NOT NULL,
          allowed_vms_json TEXT NOT NULL DEFAULT '[]');
        CREATE UNIQUE INDEX IF NOT EXISTS owner_one_active_generation
          ON owner_sessions(session_id) WHERE ended_at IS NULL;
        CREATE TABLE IF NOT EXISTS owner_operation_approvals (
          operation_id TEXT PRIMARY KEY, generation TEXT NOT NULL REFERENCES owner_sessions(generation),
          request_sha256 TEXT NOT NULL, approval_reference TEXT NOT NULL,
          approved_at INTEGER NOT NULL, vm_id TEXT);
        CREATE TABLE IF NOT EXISTS owner_operations (
          operation_id TEXT PRIMARY KEY, generation TEXT NOT NULL REFERENCES owner_sessions(generation),
          request_sha256 TEXT NOT NULL, authorization_mode TEXT NOT NULL,
          approval_reference TEXT NOT NULL, permission_revision INTEGER NOT NULL,
          state TEXT NOT NULL, dispatched_at INTEGER NOT NULL, finished_at INTEGER, vm_id TEXT);
        CREATE TABLE IF NOT EXISTS owner_permission_audit (
          id INTEGER PRIMARY KEY, time INTEGER NOT NULL, event TEXT NOT NULL,
          generation TEXT NOT NULL, reference TEXT);
        ''')
        for table,column,declaration in (
                ('owner_sessions','allowed_vms_json',"TEXT NOT NULL DEFAULT '[]'"),
                ('owner_operation_approvals','vm_id','TEXT'),('owner_operations','vm_id','TEXT')):
            if column not in {row['name'] for row in self.db.execute('PRAGMA table_info('+table+')')}:
                self.db.execute('ALTER TABLE '+table+' ADD COLUMN '+column+' '+declaration)
        need(self.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok', 'ledger-integrity-failed')

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        else:
            self.db.execute('COMMIT')

    def _audit(self,event,generation,ref=None):
        self.db.execute('INSERT INTO owner_permission_audit(time,event,generation,reference) VALUES(?,?,?,?)',
                        (int(self.clock()),event,generation,ref))

    def _session(self,session_id,generation,active=True):
        identifier(session_id,'session-id'); generation_id(generation)
        row = self.db.execute('SELECT * FROM owner_sessions WHERE session_id=? AND generation=?',
                              (session_id,generation)).fetchone()
        need(row is not None, 'unknown-session-generation')
        if active:
            need(row['ended_at'] is None, 'session-ended')
        return row

    def _end(self,row,lifecycle_reference):
        self.db.execute("UPDATE owner_sessions SET ended_at=?,end_reference=?,mode='ask_each',"
                        "approval_reference=NULL,allowed_vms_json='[]',permission_revision=permission_revision+1 WHERE generation=?",
                        (int(self.clock()),lifecycle_reference,row['generation']))
        self.db.execute('DELETE FROM owner_operation_approvals WHERE generation=?',(row['generation'],))
        self._audit('session_ended',row['generation'],lifecycle_reference)

    def start_session(self,session_id,lifecycle_reference):
        """A verified start/resume event always creates a fresh random generation.

        Repeating a start safely clears permission. An old end event must retain
        its original generation so it cannot close a replacement generation.
        """
        identifier(session_id,'session-id'); reference(lifecycle_reference)
        generation = secrets.token_hex(16)
        with self.transaction():
            old = self.db.execute('SELECT * FROM owner_sessions WHERE session_id=? AND ended_at IS NULL',
                                  (session_id,)).fetchone()
            if old is not None:
                self._end(old,lifecycle_reference)
            self.db.execute("INSERT INTO owner_sessions VALUES(?,?,?,?,NULL,NULL,'ask_each',NULL,0,'[]')",
                            (generation,session_id,lifecycle_reference,int(self.clock())))
            self._audit('session_started',generation,lifecycle_reference)
        return self.status(session_id,generation)

    def status(self,session_id,generation):
        row = self._session(session_id,generation,active=False)
        return {'version':1,**{key:row[key] for key in ('session_id','generation','mode',
            'approval_reference','permission_revision','started_at','ended_at')},
            'active':row['ended_at'] is None,'operation_count_limit':None,
            'vm_scope':json.loads(row['allowed_vms_json'])}

    def approve_session(self,session_id,generation,approval_reference,allowed_vms=None):
        """Caller has verified a human chose all operations for this session."""
        reference(approval_reference)
        allowed_vms_json = json.dumps(vm_scope(allowed_vms),separators=(',',':'))
        with self.transaction():
            row = self._session(session_id,generation)
            if (row['mode']!='session' or row['approval_reference']!=approval_reference
                    or row['allowed_vms_json']!=allowed_vms_json):
                # A removed target ends the old session authority permanently.
                # Later broadening must not resurrect a dispatched operation a
                # polling executor may not have observed during the restriction.
                narrowed = (row['mode']=='session' and not
                    set(json.loads(row['allowed_vms_json'])).issubset(json.loads(allowed_vms_json)))
                self.db.execute("UPDATE owner_sessions SET mode='session',approval_reference=?,allowed_vms_json=?,"
                                'permission_revision=permission_revision+? WHERE generation=?',
                                (approval_reference,allowed_vms_json,int(narrowed),generation))
                self.db.execute('DELETE FROM owner_operation_approvals WHERE generation=?',(generation,))
                self._audit('session_approval_recorded',generation,approval_reference)
        return self.status(session_id,generation)

    def approve_operation(self,session_id,generation,operation_id,request_sha256,approval_reference,*,vm_id=None):
        """Record human approval of this exact immutable operation envelope hash."""
        identifier(operation_id,'operation-id'); request_hash(request_sha256); reference(approval_reference)
        if vm_id is not None:
            vm_identity(vm_id)
        with self.transaction():
            self._session(session_id,generation)
            need(self.db.execute('SELECT 1 FROM owner_operations WHERE operation_id=?',
                                 (operation_id,)).fetchone() is None, 'operation-already-dispatched')
            old = self.db.execute('SELECT * FROM owner_operation_approvals WHERE operation_id=?',
                                  (operation_id,)).fetchone()
            if old is not None:
                need(old['generation']==generation and old['request_sha256']==request_sha256
                     and old['approval_reference']==approval_reference and old['vm_id']==vm_id,
                     'operation-approval-conflict')
            else:
                self.db.execute('INSERT INTO owner_operation_approvals VALUES(?,?,?,?,?,?)',
                                (operation_id,generation,request_sha256,approval_reference,int(self.clock()),vm_id))
                self._audit('operation_approval_recorded',generation,operation_id)
        return {'operation_id':operation_id,'request_sha256':request_sha256,'approval_recorded':True}

    def consume_operation(self,session_id,generation,operation_id,request_sha256,*,vm_id=None):
        """Atomically fence one dispatch before invoking the privileged transport.

        The hash covers target VM/identity, exact script bytes, arguments,
        execution identity and timeout. Caller constructs/verifies that envelope.
        A crash after this commit is uncertain; this operation ID never retries.
        """
        identifier(operation_id,'operation-id'); request_hash(request_sha256)
        if vm_id is not None:
            vm_identity(vm_id)
        with self.transaction():
            row = self._session(session_id,generation)
            need(self.db.execute('SELECT 1 FROM owner_operations WHERE operation_id=?',
                                 (operation_id,)).fetchone() is None, 'operation-already-dispatched')
            approval = row['approval_reference']
            if row['mode']=='ask_each':
                one = self.db.execute('SELECT * FROM owner_operation_approvals WHERE operation_id=?',
                                      (operation_id,)).fetchone()
                need(one is not None and one['generation']==generation, 'human-approval-required')
                need(one['request_sha256']==request_sha256 and one['vm_id']==vm_id, 'request-hash-mismatch')
                approval = one['approval_reference']
            elif row['mode']=='session':
                need(vm_id is not None and vm_id in json.loads(row['allowed_vms_json']), 'vm-outside-session-scope')
            need(row['mode'] in ('ask_each','session') and approval is not None, 'human-approval-required')
            self.db.execute("INSERT INTO owner_operations VALUES(?,?,?,?,?,?,'dispatched',?,NULL,?)",
                            (operation_id,generation,request_sha256,row['mode'],approval,
                             row['permission_revision'],int(self.clock()),vm_id))
            self.db.execute('DELETE FROM owner_operation_approvals WHERE operation_id=?',(operation_id,))
            self._audit('operation_authorization_consumed',generation,operation_id)
        return self.operation(operation_id)

    def _operation_current(self,session_id,generation,operation_id,request_sha256,vm_id):
        identifier(operation_id,'operation-id'); request_hash(request_sha256)
        if vm_id is not None:
            vm_identity(vm_id)
        session = self._session(session_id,generation)
        row = self.db.execute('SELECT * FROM owner_operations WHERE operation_id=?',
                              (operation_id,)).fetchone()
        need(row is not None and row['generation']==generation and row['request_sha256']==request_sha256
             and row['vm_id']==vm_id, 'operation-binding-mismatch')
        need(row['state']=='dispatched' and row['permission_revision']==session['permission_revision'],
             'operation-authorization-ended')
        if row['authorization_mode']=='session':
            need(session['mode']=='session' and vm_id in json.loads(session['allowed_vms_json']),
                 'vm-outside-session-scope')
        return dict(row)

    def assert_operation_current(self,session_id,generation,operation_id,request_sha256,*,vm_id=None):
        """Executor guard while supervising a process; not a dispatch primitive."""
        with self.transaction():
            return self._operation_current(session_id,generation,operation_id,request_sha256,vm_id)

    def dispatch_operation(self,session_id,generation,operation_id,request_sha256,starter_callback,*,vm_id=None):
        """Commit once-only consumption, then fence revocation through child start.

        Starter is a nonblocking process-start callback over already captured
        immutable request bytes. Never wait for transport/command completion in
        this callback: revocation must remain available after child creation.
        Consumption stays committed even if the callback or second commit fails.
        The executor owns child cleanup and recording an uncertain result.
        """
        need(callable(starter_callback), 'process-starter-required')
        self.consume_operation(session_id,generation,operation_id,request_sha256,vm_id=vm_id)
        with self.transaction():
            self._operation_current(session_id,generation,operation_id,request_sha256,vm_id)
            return starter_callback()

    def revoke_session(self,session_id,generation,revocation_reference):
        reference(revocation_reference)
        with self.transaction():
            self._session(session_id,generation)
            self.db.execute("UPDATE owner_sessions SET mode='ask_each',approval_reference=NULL,"
                            "allowed_vms_json='[]',permission_revision=permission_revision+1 WHERE generation=?",(generation,))
            self.db.execute('DELETE FROM owner_operation_approvals WHERE generation=?',(generation,))
            self._audit('session_permission_revoked',generation,revocation_reference)
        return self.status(session_id,generation)

    def end_session(self,session_id,generation,lifecycle_reference):
        reference(lifecycle_reference)
        with self.transaction():
            row = self._session(session_id,generation,active=False)
            if row['ended_at'] is None:
                self._end(row,lifecycle_reference)
        return self.status(session_id,generation)

    def finish_operation(self,session_id,generation,operation_id,request_sha256,state):
        """Record an observed result even after revocation; never grant authority."""
        identifier(operation_id,'operation-id'); request_hash(request_sha256)
        need(state in ('completed','failed','uncertain'), 'invalid-operation-result')
        with self.transaction():
            self._session(session_id,generation,active=False)
            row = self.db.execute('SELECT * FROM owner_operations WHERE operation_id=?',
                                  (operation_id,)).fetchone()
            need(row is not None and row['generation']==generation and row['request_sha256']==request_sha256,
                 'operation-binding-mismatch')
            need(row['state']=='dispatched', 'operation-already-finished')
            self.db.execute('UPDATE owner_operations SET state=?,finished_at=? WHERE operation_id=?',
                            (state,int(self.clock()),operation_id))
            self._audit('operation_result_'+state,generation,operation_id)
        return self.operation(operation_id)

    def operation(self,operation_id):
        identifier(operation_id,'operation-id')
        row = self.db.execute('SELECT * FROM owner_operations WHERE operation_id=?',(operation_id,)).fetchone()
        need(row is not None, 'unknown-operation')
        return dict(row)
