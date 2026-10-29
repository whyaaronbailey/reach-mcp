"""Source publication checks use only synthetic samples and temporary Git repos."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-public-source.py"
SPEC = importlib.util.spec_from_file_location("public_source_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class PublicSourceTests(unittest.TestCase):
    def rules(self, text, path="source.py"):
        return {finding.rule for finding in CHECK.scan_text(path, text)}

    def test_rejects_credential_patterns_without_returning_values(self):
        samples = (
            ("github-token", "ghp_" + "x" * 36),
            ("private-key", "-----BEGIN " + "RSA PRIVATE KEY-----"),
            ("aws-access-key", "AKIA" + "X" * 16),
            ("ssh-key-material", "ssh-ed25519 " + "A" * 70),
            ("api-token", "sk-proj-" + "X" * 40),
            ("jwt-token", "eyJ" + "x" * 20 + "." + "y" * 20 + "." + "z" * 20),
        )
        for rule, sample in samples:
            with self.subTest(rule=rule):
                findings = CHECK.scan_text("source.py", sample)
                self.assertIn(rule, {finding.rule for finding in findings})
                self.assertNotIn(sample, repr(findings))

    def test_real_domain_and_profile_are_rejected(self):
        domain = "device.private-network." + "ts.net"
        self.assertIn("tailnet-identity", self.rules(domain))
        self.assertIn("personal-profile-path", self.rules("/Users/" + "person-name/project"))
        self.assertIn("personal-profile-path", self.rules("C:" + "\\Users\\person-name\\project"))

    def test_examples_and_loopback_are_accepted(self):
        text = "https://your-device.your-tailnet.ts.net https://reach.example.invalid 192.0.2.5 198.51.100.12 203.0.113.8 127.0.0.1 /Users/owner /home/runner C:\\Users\\Example mail@example.com"
        self.assertEqual(self.rules(text), set())

    def test_private_hosts_and_email_are_rejected(self):
        self.assertIn("private-network-host", self.rules("10." + "23.45.67"))
        self.assertIn("private-network-host", self.rules("100." + "85.10.20"))
        self.assertIn("private-network-host", self.rules("10." + "23.45.67/32"))
        self.assertIn("private-network-host", self.rules("10." + "23.0.0/16"))
        self.assertEqual(self.rules("10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10"), set())
        self.assertIn("personal-email", self.rules("person@" + "mail-provider.com"))

    def test_credential_url_example_is_allowed_only_in_test(self):
        value = "http://user:password@127.0.0.1:8000"
        self.assertEqual(self.rules(value, "test_urls.py"), set())
        self.assertIn("credential-url", self.rules(value))
        self.assertIn("credential-url", self.rules("https://alice:" + "credential@service.example.invalid", "test_urls.py"))

    def test_forbidden_runtime_files(self):
        for name in (".env", ".env.production", "secrets/config.json", "logs/a.jsonl", "config.toml", "private.key", "capture.zip"):
            with self.subTest(name=name):
                self.assertEqual(CHECK.scan_path(name)[0].rule, "runtime-artifact")
        for name in ("config.example.toml", ".env.example", "gateway/runtime-files.example.json", "src/config.py"):
            self.assertEqual(CHECK.scan_path(name), [])

    def test_line_numbers_and_non_text_refusal(self):
        self.assertEqual(CHECK.scan_text("source.py", "safe\n" + "ghp_" + "x" * 36)[0].line, 2)
        self.assertEqual(CHECK.scan_bytes("source.py", b"\xff")[0].rule, "binary-or-non-utf8")
        self.assertEqual(CHECK.scan_bytes("source.py", b"binary\0payload")[0].rule, "binary-or-non-utf8")

    def test_untracked_and_history_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.run(["git", "-C", directory, *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            git("init", "--quiet")
            git("config", "user.name", "Test Contributor")
            git("config", "user.email", "test@example.com")
            (root / "old.py").write_text("ghp_" + "x" * 36, encoding="utf-8")
            git("add", "old.py")
            git("commit", "--quiet", "-m", "synthetic fixture")
            (root / "old.py").write_text("safe", encoding="utf-8")
            git("add", "old.py")
            git("commit", "--quiet", "-m", "remove fixture")
            (root / "untracked.py").write_text("/Users/" + "person-name/project", encoding="utf-8")
            current, _ = CHECK.working_tree(root)
            self.assertEqual({f.rule for f in current}, {"personal-profile-path"})
            old, count = CHECK.history(root)
            self.assertGreaterEqual(count, 2)
            self.assertIn("github-token", {f.rule for f in old})
            self.assertTrue(all("ghp_" not in repr(f) for f in old))
            git("config", "user.email", "person@" + "mail-provider.com")
            git("commit", "--quiet", "--allow-empty", "-m", "synthetic email fixture")
            metadata, _ = CHECK.history(root)
            self.assertIn("commit-email", {f.rule for f in metadata})
            self.assertTrue(all("mail-provider.com" not in repr(f) for f in metadata))


if __name__ == "__main__":
    unittest.main()
