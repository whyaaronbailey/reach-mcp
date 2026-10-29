"""Fixed owner TLS diagnostic; no credentials, HTTP requests, or desktop actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
from urllib.parse import urlsplit


def read_json(path, limit=524288):
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError("diagnostic input limit")
    return json.loads(raw)


def selected_origin(value, profile):
    if not isinstance(value, str):
        raise ValueError("invalid private origin")
    parsed = urlsplit(value)
    if (profile.get("version") != 2 or profile.get("transport") != "private-outbound-tls"
        or profile.get("oauth_route") is not False or value not in profile.get("gateways", [])
        or parsed.scheme != "https" or not parsed.hostname or parsed.port != 19444
        or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
        or not re.fullmatch("[a-f0-9]{64}", profile.get("ca_sha256", ""))):
        raise ValueError("unapproved private origin")
    return parsed.hostname


def tls_probe(root, vm_id):
    """Caller validates protected package/runtime ACLs and all package hashes first."""
    config = read_json(root / "worker.json")
    profile = read_json(root / "gateway-profile.json")
    if config.get("vm_id") != vm_id:
        raise ValueError("identity mismatch")
    host = selected_origin(config.get("gateway"), profile)
    ca = root / "gateway-ca.crt"
    if hashlib.sha256(ca.read_bytes()).hexdigest() != profile["ca_sha256"]:
        raise ValueError("CA hash mismatch")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(ca))
    # AF_INET matches the explicitly IPv4-only gateway transport policy.
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(
        host, 19444, socket.AF_INET, socket.SOCK_STREAM)})
    if not 1 <= len(addresses) <= 4:
        raise ValueError("private address count")
    failure = None
    for address in addresses:
        try:
            observed = verified_socket(host, address, context)
            return {**observed, "verified": True, "ca_sha256": profile["ca_sha256"],
                    "url": config["gateway"]}
        except (OSError, ssl.SSLError) as exc:
            failure = exc
    raise ValueError("private TLS verification failed") from failure


def verified_socket(host, address, context, port=19444):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.settimeout(5)
        raw.connect((address, port))
        with context.wrap_socket(raw, server_hostname=host) as channel:
            return {"source_address": channel.getsockname()[0],
                    "destination_address": address,
                    "leaf_sha256": hashlib.sha256(ssl.DER_cert_to_PEM_cert(channel.getpeercert(binary_form=True)).encode("ascii")).hexdigest(),
                    "protocol": channel.version()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vm-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch("[a-z0-9][a-z0-9-]{0,63}", args.vm_id):
        raise ValueError("invalid VM identity")
    if os.name != "nt":
        raise ValueError("Windows owner diagnostic required")
    root = Path(os.environ["ProgramData"]) / "ReachGateway" / args.vm_id
    if root.resolve() != Path(__file__).resolve().parent:
        raise ValueError("installed diagnostic required")
    print(json.dumps(tls_probe(root, args.vm_id), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"verified":false,"error":"Private TLS diagnostic failed."}')
        raise SystemExit(1)
