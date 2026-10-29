"""Owner diagnostic security boundaries with disposable TLS, no desktop actions."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import boundary_probe as b


class BoundaryProbeTests(unittest.TestCase):
    def test_reviewed_private_origins_only(self):
        profile = {"version": 2, "transport": "private-outbound-tls", "oauth_route": False,
                   "gateways": ["https://fixture.test:19444"], "ca_sha256": "a" * 64}
        self.assertEqual("fixture.test", b.selected_origin(profile["gateways"][0], profile))
        for candidate in ("http://fixture.test:19444", "https://fixture.test:443",
                          "https://fixture.test:19444/worker/next",
                          "https://fixture.test:19444?x=1", "https://user@fixture.test:19444",
                          "https://arbitrary.test:19444"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                b.selected_origin(candidate, profile)

    def test_wrong_vm_and_ca_fail_before_network(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "worker.json").write_text(json.dumps({"vm_id": "right", "gateway": "https://fixture.test:19444"}))
            (root / "gateway-profile.json").write_text(json.dumps({"version": 2,
                "transport": "private-outbound-tls", "oauth_route": False,
                "gateways": ["https://fixture.test:19444"], "ca_sha256": "a" * 64}))
            (root / "gateway-ca.crt").write_bytes(b"not the approved CA")
            with patch.object(b.socket, "getaddrinfo", side_effect=AssertionError("network must not run")):
                for vm in ("wrong", "right"):
                    with self.assertRaises(ValueError):
                        b.tls_probe(root, vm)

    def tls_case(self, trusted=True, hostname="fixture.test"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
                .not_valid_after(now+timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.test")]), critical=False)
                .sign(key, hashes.SHA256()))
            certpath, keypath = root / "ca.pem", root / "key.pem"
            certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(certpath, keypath)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if trusted:
                client_context.load_verify_locations(cafile=str(certpath))
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]
                def serve():
                    try:
                        conn, _ = listener.accept()
                        with conn:
                            with server_context.wrap_socket(conn, server_side=True):
                                pass
                    except (OSError, ssl.SSLError):
                        pass
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                try:
                    result = b.verified_socket(hostname, "127.0.0.1", client_context, port)
                    self.assertEqual(hashlib.sha256(certpath.read_bytes()).hexdigest(), result["leaf_sha256"])
                    return result
                finally:
                    thread.join(6)
                    self.assertFalse(thread.is_alive())

    def test_real_tls_hostname_and_trust_succeed(self):
        result = self.tls_case()
        self.assertEqual("127.0.0.1", result["source_address"])
        self.assertRegex(result["leaf_sha256"], "^[a-f0-9]{64}$")

    def test_real_tls_rejects_wrong_hostname(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.tls_case(hostname="wrong.test")

    def test_real_tls_rejects_untrusted_certificate(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.tls_case(trusted=False)


if __name__ == "__main__":
    unittest.main()
