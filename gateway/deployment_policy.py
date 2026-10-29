"""Protected deployment policy and independent per-VM transport evidence.

These validators do not create evidence. Only the pinned owner-side host checker
may attest observed Docker/firewall/guest state. No listener writes these files.
Shared policy contains no VM list: adding or revoking one profile does not alter
another profile's digest or require a gateway restart.
"""
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import socket
import time
from urllib.parse import urlsplit

from channel import ChannelDenied, loads
from registry import (HEARTBEAT_TTL, hex_id, machine_identity, require,
                      sid_identity, vm_identity)

PROOF_FLAGS = frozenset({'tls_verified','guest_filter_verified','host_filter_verified',
                        'container_egress_verified','private_routes_not_public'})
RUNTIME_FLAGS = frozenset({'guards_restored','image_verified','network_verified',
                          'container_spec_verified'})


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def version(value, expected):
    require(type(value) is int and value == expected)


def sha(value):
    require(isinstance(value,str) and re.fullmatch(r'[a-f0-9]{64}',value))
    return value


def digest(value):
    """Canonical JSON digest; arrays remain ordered and booleans stay typed."""
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                     ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()


def timestamp(value, now, fresh=True):
    require(type(value) is int and 0 <= value <= now + 10)
    if fresh:
        require(now - 120 <= value)


def safe_name(value):
    require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',value))
    return value


def private_url(value):
    require(isinstance(value,str))
    try:
        parsed=urlsplit(value)
        require(parsed.scheme=='https' and parsed.hostname and parsed.port==19444
                and parsed.path=='' and not parsed.query and not parsed.fragment
                and not parsed.username and not parsed.password)
        require(value=='https://'+parsed.netloc and parsed.netloc==parsed.netloc.lower())
    except (ValueError,TypeError):
        raise ChannelDenied() from None
    return value


def policy(value):
    exact(value, {'version','deployment_id','manifest_sha256','transport_sha256',
        'image_id','checker_sha256','container_spec_sha256','hostname_mode',
        'tls','public','network','runtime_root'})
    version(value['version'],1); hex_id(value['deployment_id'])
    for field in ('manifest_sha256','transport_sha256','checker_sha256','container_spec_sha256'):
        sha(value[field])
    require(isinstance(value['image_id'],str) and value['image_id'].startswith('sha256:'))
    sha(value['image_id'][7:])
    # This is an explicit deployment constraint, not an assumption about Docker.
    require(value['hostname_mode']=='docker-container-id-prefix')
    root=value['runtime_root']
    require(isinstance(root,str) and str(PurePosixPath(root))==root and root.startswith('/')
            and root!='/' and '..' not in PurePosixPath(root).parts)
    tls=value['tls'];exact(tls,{'ca_sha256','leaf_sha256','private_urls'})
    sha(tls['ca_sha256']);sha(tls['leaf_sha256'])
    urls=tls['private_urls']
    require(type(urls) is list and 1<=len(urls)<=4 and len(set(urls))==len(urls))
    for url in urls: private_url(url)
    public=value['public'];exact(public,{'origin','mcp_path','oauth_prefix'})
    try:
        parsed=urlsplit(public['origin'])
        require(parsed.scheme=='https' and parsed.hostname and parsed.path==''
            and not parsed.query and not parsed.fragment and not parsed.username and not parsed.password
            and parsed.port in (None,443))
    except (ValueError,TypeError):
        raise ChannelDenied() from None
    for field in ('mcp_path','oauth_prefix'):
        require(isinstance(public[field],str) and re.fullmatch(r'/[a-z0-9][a-z0-9/-]{0,63}',public[field])
                and not public[field].endswith('/'))
    require(public['mcp_path']!=public['oauth_prefix'])
    network=value['network'];exact(network,{'name','subnet','gateway','container_ip'})
    safe_name(network['name'])
    try:
        subnet=ipaddress.ip_network(network['subnet'],strict=True)
        gateway=ipaddress.ip_address(network['gateway']);address=ipaddress.ip_address(network['container_ip'])
        require(subnet.version==4 and subnet.is_private and gateway in subnet and address in subnet
                and gateway!=address and gateway not in (subnet.network_address,subnet.broadcast_address)
                and address not in (subnet.network_address,subnet.broadcast_address))
    except (ValueError,TypeError):
        raise ChannelDenied() from None
    return value


def profile(value, shared):
    policy(shared)
    exact(value, {'version','vm_id','machine_uuid','account_sid','enabled','kind',
                  'worker_url','source_addresses','guest_policy_sha256','adapter'})
    version(value['version'],1);vm_identity(value['vm_id'])
    machine_identity(value['machine_uuid']);sid_identity(value['account_sid'])
    require(type(value['enabled']) is bool)
    require(private_url(value['worker_url']) in shared['tls']['private_urls'])
    sha(value['guest_policy_sha256'])
    sources=value['source_addresses']
    require(type(sources) is list and 1<=len(sources)<=8 and len(set(sources))==len(sources))
    try:
        addresses=[ipaddress.ip_address(source) for source in sources]
        require(all(address.version==4 and str(address)==source and not address.is_loopback
            and not address.is_multicast and not address.is_unspecified
            for source,address in zip(sources,addresses)))
    except (ValueError,TypeError):
        raise ChannelDenied() from None
    adapter=value['adapter']
    if value['kind']=='libvirt-isolated':
        exact(adapter,{'domain_uuid','network_name','nwfilter_name','nwfilter_sha256','mac_address'})
        # Libvirt domain UUID and guest SMBIOS UUID are separate stable identities.
        # The owner collector must verify their explicit domain XML/QGA mapping.
        machine_identity(adapter['domain_uuid'])
        safe_name(adapter['network_name']);safe_name(adapter['nwfilter_name']);sha(adapter['nwfilter_sha256'])
        require(isinstance(adapter['mac_address'],str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',adapter['mac_address']))
        require(all(address.is_private for address in addresses))
    elif value['kind']=='windows-tailnet':
        exact(adapter,{'node_id','node_key','interface'})
        require(isinstance(adapter['node_id'],str) and re.fullmatch(r'[A-Za-z0-9]{1,64}',adapter['node_id']))
        require(isinstance(adapter['node_key'],str) and re.fullmatch(r'nodekey:[a-f0-9]{64}',adapter['node_key']))
        require(isinstance(adapter['interface'],str) and re.fullmatch(r'tailscale[0-9]{1,6}',adapter['interface']))
        require(all(address in ipaddress.ip_network('100.64.0.0/10') for address in addresses))
    else:
        raise ChannelDenied()
    return value


def runtime(value, shared, *, host_boot_id, container_hostname, now=None, fresh=False):
    policy(shared)
    now=time.time() if now is None else now
    exact(value, {'version','deployment_id','policy_sha256','checked_at','host_boot_id',
        'container_id','image_id','network_id','container_hostname','container_spec_sha256',
        'shared_rules_sha256'} | RUNTIME_FLAGS)
    version(value['version'],1);timestamp(value['checked_at'],now,fresh)
    require(value['deployment_id']==shared['deployment_id'] and value['policy_sha256']==digest(shared))
    require(machine_identity(value['host_boot_id'])==machine_identity(host_boot_id))
    sha(value['container_id']);sha(value['network_id']);sha(value['shared_rules_sha256'])
    require(value['image_id']==shared['image_id']
            and value['container_spec_sha256']==shared['container_spec_sha256'])
    require(value['container_hostname']==value['container_id'][:12]
            and container_hostname==value['container_hostname'])
    for field in RUNTIME_FLAGS: require(value[field] is True)
    return value


def observed_identity():
    """Read-only Linux facts; never discover identity through Docker's socket."""
    return {'host_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text('ascii').strip(),
            'container_hostname':socket.gethostname()}


def deployment_context(read_json, read_bytes, *, now=None, fresh=False, observation=None):
    """Read every input through the caller's protected owner-path reader."""
    shared=policy(read_json('/run/config/deployment-policy.json'))
    security=read_json('/run/config/security.json')
    require(type(security) is dict)
    for field in ('manifest_sha256','transport_sha256'):
        require(security.get(field)==shared[field])
    transport_raw=read_bytes('/run/config/transport.json',8192)
    require(hashlib.sha256(transport_raw).hexdigest()==shared['transport_sha256'])
    transport=loads(transport_raw,8192)
    exact(transport,{'version','private_urls'});version(transport['version'],2)
    require(transport['private_urls']==shared['tls']['private_urls'])
    for path,field in (('/run/tls/ca.crt','ca_sha256'),('/run/tls/server.crt','leaf_sha256')):
        require(hashlib.sha256(read_bytes(path,65536)).hexdigest()==shared['tls'][field])
    facts=observed_identity() if observation is None else observation
    attestation=runtime(read_json('/run/config/runtime-attestation.json'),shared,
                        now=now,fresh=fresh,**facts)
    return {'policy':shared,'runtime':attestation,'observation':facts}


def verify_network_proof(registry, vm_id, proof, shared, selected, attestation,
                         *, observation=None, now=None):
    """A fresh per-VM observation binds an existing live authenticated session."""
    vm_id=vm_identity(vm_id);now=time.time() if now is None else now
    selected=profile(selected,shared)
    require(selected['enabled'] is True and selected['vm_id']==vm_id)
    facts=observed_identity() if observation is None else observation
    runtime(attestation,shared,now=now,**facts)
    vm=registry.get(vm_id);connection=registry.owner_connection(vm_id)
    require(not vm['revoked'] and connection is not None and connection['desktop_state']=='ready'
            and 0<=now-connection['last_seen']<=HEARTBEAT_TTL)
    registry.assert_epoch(connection['gateway_epoch'])
    expected={'version','vm_id','machine_uuid','account_sid','connection_id','gateway_epoch',
        'checked_at','manifest_sha256','transport_sha256','policy_sha256','profile_sha256',
        'runtime_sha256','checker_sha256','host_boot_id','container_id','network_id','observation_id'} | PROOF_FLAGS
    exact(proof,expected);version(proof['version'],3)
    timestamp(proof['checked_at'],now);hex_id(proof['observation_id'])
    require(proof['checked_at']>=attestation['checked_at'])
    for field in ('vm_id','machine_uuid','account_sid'):
        require(proof[field]==vm[field]==selected[field])
    for field in ('connection_id','gateway_epoch'): require(proof[field]==connection[field])
    for field in ('manifest_sha256','transport_sha256','checker_sha256'): require(proof[field]==shared[field])
    for field in ('host_boot_id','container_id','network_id'): require(proof[field]==attestation[field])
    require(proof['policy_sha256']==digest(shared) and proof['profile_sha256']==digest(selected)
            and proof['runtime_sha256']==digest(attestation))
    for field in PROOF_FLAGS: require(proof[field] is True)
