"""Owner console CLI; never mounted on either HTTP listener.

Run in the fixed gateway container from the authenticated Nexus owner console.
Grant output is a short-lived enrollment secret, written once to a protected file.
No command, file or vault administrative authority is exposed to MCP.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import sys

from channel import loads, encoded, ChannelDenied
from registry import Registry, vm_identity
from deployment_policy import (deployment_context, digest, policy, profile,
                               verify_network_proof)


def _trusted(info, directory=False, private=False):
    """Unix deployment only: root/current owner, no mutable foreign ownership."""
    if not hasattr(os, 'geteuid'):
        raise ValueError('Owner file operations require the Unix gateway console.')
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(info.st_mode) or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & (0o077 if private else 0o022)):
        raise ValueError('Protected owner path required.')


def _parent_chain(path, private_parent=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('An absolute canonical owner path is required.')
    # lstat every ancestor; no resolve(), which would hide a symlink.
    for parent in reversed(path.parents):
        _trusted(parent.lstat(), directory=True,
                 private=private_parent and parent == path.parent)
    return path


def protected_bytes(path, maximum=16384):
    path = _parent_chain(path)
    original = path.lstat()
    _trusted(original)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as source:
        current = os.fstat(source.fileno())
        _trusted(current)
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError('Owner input changed during validation.')
        if current.st_size > maximum:
            raise ValueError('Owner input exceeds its size bound.')
        data = source.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('Owner input exceeds its size bound.')
        return data


def protected_file(path, maximum=16384):
    return loads(protected_bytes(path, maximum), maximum)


@contextmanager
def secret_output(path):
    """Reserve a protected output before minting a grant; never overwrite."""
    target = _parent_chain(path, private_parent=True)
    # All ancestors are protected, and O_EXCL rejects existing files and links.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
    complete = False
    try:
        with os.fdopen(fd, 'wb') as output:
            _trusted(os.fstat(output.fileno()), private=True)
            yield output
            output.flush()
            os.fsync(output.fileno())
        complete = True
    finally:
        if not complete:
            # Only the brand-new file in the checked owner directory is removed.
            target.unlink(missing_ok=True)


def write_secret(path, value):
    with secret_output(path) as output:
        output.write(encoded(value))


def persistent_context(vm_id, *, context=None, selected=None):
    """Current protected configuration for a standing owner authorization.

    Boot/container attestations must still verify, but their changing IDs and
    timestamps are not part of owner consent. The stable policy, VM profile and
    security configuration are; changing any requires a new owner grant.
    """
    vm_id = vm_identity(vm_id)
    context = deployment_context(protected_file,protected_bytes) if context is None else context
    selected = profile(protected_file('/run/config/profiles/'+vm_id+'.json')
                       if selected is None else selected,context['policy'])
    if selected['enabled'] is not True or selected['vm_id'] != vm_id:
        raise ChannelDenied()
    security = protected_file('/run/config/security.json')
    if type(security) is not dict or any(security.get(field)!=context['policy'][field]
            for field in ('manifest_sha256','transport_sha256')):
        raise ChannelDenied()
    return {'policy_sha256':digest(context['policy']),'profile_sha256':digest(selected),
            'security_sha256':digest(security)}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db', default='/state/registry.sqlite3')
    commands=p.add_subparsers(dest='action',required=True)
    commands.add_parser('status')
    grant=commands.add_parser('grant')
    grant.add_argument('--request',required=True)
    grant.add_argument('--subject',required=True)
    grant.add_argument('--out',required=True)
    grant.add_argument('--ttl',type=int,default=600)
    lease=commands.add_parser('lease')
    lease.add_argument('--vm-id',required=True)
    lease.add_argument('--subject',required=True)
    lease.add_argument('--seconds',type=int,default=7200)
    persistent=commands.add_parser('authorize-persistent',
        help='Grant desktop authorization until owner pause/revocation; requires fresh boundary proof.')
    persistent.add_argument('--vm-id',required=True)
    persistent.add_argument('--subject',required=True)
    for action in ('pause','revoke','connection','revoke-persistent'):
        commands.add_parser(action).add_argument('--vm-id',required=True)
    return p


def main():
    os.umask(0o077)
    args=parser().parse_args()
    # Validate before opening the DB or deriving any proof pathname.
    if hasattr(args, 'vm_id'):
        args.vm_id = vm_identity(args.vm_id)
    registry=Registry(args.db,authorization_context=persistent_context)
    try:
        if args.action=='status':
            result={'vms':registry.list_vms()}
        elif args.action=='grant':
            request=protected_file(args.request)
            required={'version','vm_id','display_name','machine_uuid','account_sid'}
            if type(request) is not dict or not required <= set(request) or type(request['version']) is not int or request['version']!=2:
                raise ValueError('Installer preflight identity is required.')
            vm_identity(request['vm_id'])
            if not re.fullmatch('[1-9][0-9]{0,19}',args.subject):
                raise ValueError('Immutable numeric owner identity is required.')
            shared=policy(protected_file('/run/config/deployment-policy.json'))
            selected=profile(protected_file('/run/config/profiles/'+request['vm_id']+'.json'),shared)
            if (selected['enabled'] is not True or any(request[field]!=selected[field]
                    for field in ('vm_id','machine_uuid','account_sid'))):
                raise ChannelDenied()
            # Reserve a valid, private, non-existing output BEFORE changing grants.
            with secret_output(args.out) as output:
                value=registry.grant(request['vm_id'],request['display_name'],request['machine_uuid'],
                    request['account_sid'],[args.subject],ttl=args.ttl)
                output.write(encoded(value))
            result={'vm_id':request['vm_id'],'enrollment_grant_created':True,
                'expires_at':value['expires_at'],'desktop_lease_created':False}
        elif args.action=='connection':
            result=registry.owner_connection(args.vm_id)
            if result is None: raise ChannelDenied()
        elif args.action in ('lease','authorize-persistent'):
            # Fixed root-controlled evidence location. No listener can write it.
            proof=protected_file('/run/config/proofs/'+args.vm_id+'.json')
            context=deployment_context(protected_file,protected_bytes)
            selected=protected_file('/run/config/profiles/'+args.vm_id+'.json')
            verify_network_proof(registry,args.vm_id,proof,context['policy'],selected,
                context['runtime'],observation=context['observation'])
            expected_connection={field:proof[field] for field in ('connection_id','gateway_epoch')}
            if args.action=='authorize-persistent':
                # Bind the grant to the exact policy/profile verified by this
                # proof. Registry independently re-reads protected current state
                # while checking the exact live connection; changed inputs fail.
                result=registry.authorize_persistent(args.vm_id,args.subject,
                    persistent_context(args.vm_id,context=context,selected=selected),
                    expected_connection=expected_connection)
            else:
                result=registry.authorize_lease(args.vm_id,args.subject,seconds=args.seconds,
                    expected_connection=expected_connection)
        elif args.action=='pause':
            result=registry.pause(args.vm_id)
        elif args.action=='revoke-persistent':
            result=registry.revoke_persistent(args.vm_id)
        else:
            result=registry.revoke(args.vm_id)
        print(json.dumps(result,separators=(',',':')))
    finally:
        registry.close()


if __name__=='__main__':
    try:
        main()
    except Exception:
        print('Owner Reach operation refused. Check identity, protected inputs, connectivity and fresh boundary proof.',file=sys.stderr)
        raise SystemExit(1)
