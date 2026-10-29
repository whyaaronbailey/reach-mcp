"""Fixed private ledger command. No network, VM transport, credential or payload.

Executed in the already pinned Python image, with only /code:ro and /state:rw.
The Nexus-root PHP controller holds its host lock across consume and dispatch.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, '/code')
from owner_session_permissions import OwnerSessionPermissions, PermissionDenied


def main():
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise PermissionDenied('ledger-request-bound')
    value = json.loads(raw)
    if type(value) is not dict:
        raise PermissionDenied('ledger-request-shape')
    command = value.pop('command')
    allowed = {
        'start': {'session_id', 'reference'},
        'status': {'session_id', 'generation'},
        'allow-session': {'session_id', 'generation', 'approval_reference', 'vm_scope'},
        'approve-once': {'session_id', 'generation', 'approval_reference', 'vm_id', 'operation_id', 'request_sha256'},
        'consume': {'session_id', 'generation', 'vm_id', 'operation_id', 'request_sha256'},
        'assert': {'session_id', 'generation', 'vm_id', 'operation_id', 'request_sha256'},
        'revoke': {'session_id', 'generation', 'reference'},
        'end': {'session_id', 'generation', 'reference'},
        'finish': {'session_id', 'generation', 'operation_id', 'request_sha256', 'state'},
    }
    if command not in allowed or set(value) != allowed[command]:
        raise PermissionDenied('ledger-request-fields')
    db = OwnerSessionPermissions(Path('/state/permissions.sqlite3'))
    try:
        sid = value['session_id']
        generation = value.get('generation')
        if command == 'start':
            result = db.start_session(sid, value['reference'])
        elif command == 'status':
            result = db.status(sid, generation)
        elif command == 'allow-session':
            result = db.approve_session(sid, generation, value['approval_reference'], allowed_vms=value['vm_scope'])
        elif command == 'approve-once':
            result = db.approve_operation(sid, generation, value['operation_id'], value['request_sha256'],
                                          value['approval_reference'], vm_id=value['vm_id'])
        elif command == 'consume':
            result = db.consume_operation(sid, generation, value['operation_id'], value['request_sha256'], vm_id=value['vm_id'])
        elif command == 'assert':
            result = db.assert_operation_current(sid, generation, value['operation_id'], value['request_sha256'], vm_id=value['vm_id'])
        elif command == 'revoke':
            result = db.revoke_session(sid, generation, value['reference'])
        elif command == 'end':
            result = db.end_session(sid, generation, value['reference'])
        else:
            result = db.finish_operation(sid, generation, value['operation_id'], value['request_sha256'], value['state'])
        print(json.dumps({'ok': True, 'result': result}, separators=(',', ':')))
    finally:
        db.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if isinstance(error, PermissionDenied) else 'private-ledger-refused'
        print(json.dumps({'ok': False, 'reason': reason, 'automatic_retry': False}))
        raise SystemExit(1)
