#!/usr/bin/env python3
"""Check publication sources without printing any matching credential contents.

This is a conservative source-publication guard, not a proof that arbitrary text
contains no private information. Review new files and changes as well. Synthetic
examples belong on example domains and documentation IP ranges. Keep deployment
configuration, credential material, logs, and captures outside the repository.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str


TOKEN_RULES = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("api-token", re.compile(r"\bsk-(?:proj-|ant-api[0-9]+-)[A-Za-z0-9_-]{20,}\b")),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("ssh-key-material", re.compile(r"\bssh-(?:ed25519|rsa|dss|ecdsa)\s+[A-Za-z0-9+/]{40,}={0,3}")),
)
TAILNET = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.ts\.net\b", re.I)
PROFILE = re.compile(r"(?:[A-Z]:[\\/]+Users[\\/]+|/Users/|/home/)([A-Za-z0-9_.+-]+)", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
CREDENTIAL_URL = re.compile(r"\b(?:https?|ssh)://([^\s/@:]+):([^\s/@]+)@([^\s/'\"<>]+)", re.I)
GENERIC_USERS = frozenset({"owner", "user", "username", "example", "public", "default", "test", "runner", "reachagent"})
# One existing negative URL-validation fixture uses this familiar example LAN IP.
# New fixtures should use the documentation ranges, not add production addresses.
LEGACY_EXAMPLE_IPS = frozenset({".".join(("192", "168", "1", "2"))})
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
))
FORBIDDEN_DIRS = frozenset({"secrets", "logs", "backups", "local-deployment", "state", ".state", "captures", "screenshots", "session-exports"})
FORBIDDEN_SUFFIXES = frozenset({".key", ".pem", ".pfx", ".p12", ".crt", ".cer", ".sqlite", ".sqlite3", ".db", ".jsonl", ".log", ".tar", ".zip", ".whl"})
FORBIDDEN_NAMES = frozenset({"config.toml", "deployment.json", "registry.json", "approved.json", "authorized_keys", "known_hosts"})
MAX_SOURCE_BYTES = 8 * 1024 * 1024


def example_domain(domain: str) -> bool:
    value = domain.lower().rstrip(".").split(":", 1)[0]
    return value in {"example", "localhost"} or any(
        value == suffix or value.endswith("." + suffix)
        for suffix in ("example.com", "example.net", "example.org", "example.test", "example.invalid", "invalid", "test")
    )


def allowed_email(domain: str) -> bool:
    return example_domain(domain) or domain.lower() == "users.noreply.github.com"


def scan_path(path: str) -> list[Finding]:
    source = PurePosixPath(path.replace("\\", "/"))
    parts = {part.lower() for part in source.parts}
    name = source.name.lower()
    forbidden_env = name == ".env" or (name.startswith(".env.") and name != ".env.example")
    if parts & FORBIDDEN_DIRS or source.suffix.lower() in FORBIDDEN_SUFFIXES or name in FORBIDDEN_NAMES or forbidden_env:
        return [Finding(path, 0, "runtime-artifact")]
    return []


def scan_text(path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    is_test = PurePosixPath(path).name.startswith("test_")
    for number, line in enumerate(content.splitlines(), 1):
        rules = {name for name, pattern in TOKEN_RULES if pattern.search(line)}
        for match in TAILNET.finditer(line):
            labels = match.group().lower().split(".")[:-2]
            if not any(label.startswith(("your-", "example-")) or label in {"example", "your-tailnet", "tailnet"} for label in labels):
                rules.add("tailnet-identity")
        if any(match.group(1).lower() not in GENERIC_USERS for match in PROFILE.finditer(line)):
            rules.add("personal-profile-path")
        for match in IPV4.finditer(line):
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            # Permit the standard RFC range definitions, not host /32s or an
            # installation's own subnet. Other examples use documentation IPs.
            suffix = re.match(r"/([0-9]{1,2})(?![0-9])", line[match.end():])
            is_standard_range = suffix is not None and any(
                str(address) + suffix.group() == str(network) for network in PRIVATE_NETWORKS
            )
            if any(address in network for network in PRIVATE_NETWORKS) and not is_standard_range:
                if not (is_test and str(address) in LEGACY_EXAMPLE_IPS):
                    rules.add("private-network-host")
        for match in EMAIL.finditer(line):
            if not allowed_email(match.group(1)):
                rules.add("personal-email")
        for match in CREDENTIAL_URL.finditer(line):
            username, password, host = match.groups()
            if not (is_test and username == "user" and password == "password" and (example_domain(host) or host.startswith("127.0.0.1:"))):
                rules.add("credential-url")
        findings.extend(Finding(path, number, rule) for rule in sorted(rules))
    return findings


def scan_bytes(path: str, payload: bytes) -> list[Finding]:
    findings = scan_path(path)
    if len(payload) > MAX_SOURCE_BYTES:
        return findings + [Finding(path, 0, "oversize-source")]
    if b"\0" in payload:
        return findings + [Finding(path, 0, "binary-or-non-utf8")]
    try:
        content = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return findings + [Finding(path, 0, "binary-or-non-utf8")]
    return findings + scan_text(path, content)


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError("git-read-failed")
    return result.stdout


def working_tree(root: Path) -> tuple[list[Finding], int]:
    paths = set(git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").decode("utf-8").split("\0")) - {""}
    findings: list[Finding] = []
    count = 0
    for name in sorted(paths):
        path = root / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            findings.append(Finding(name, 0, "unsupported-file-type"))
            continue
        findings.extend(scan_bytes(name, path.read_bytes()))
        count += 1
    return findings, count


def history(root: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    checked: set[tuple[str, str]] = set()
    commits = git(root, "log", "--all", "--format=%H%x00%ae%x00%ce").decode("utf-8").splitlines()
    for record in commits:
        commit, author, committer = record.split("\0")
        for email in (author, committer):
            domain = email.rpartition("@")[2]
            if not domain or not allowed_email(domain):
                findings.append(Finding("commit:" + commit[:12], 0, "commit-email"))
        for item in git(root, "ls-tree", "-rz", commit).split(b"\0"):
            if not item:
                continue
            metadata, name_bytes = item.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split(" ")
            name = name_bytes.decode("utf-8")
            if kind != "blob":
                continue
            key = (name, oid)
            if key in checked:
                continue
            checked.add(key)
            label = "history:" + oid[:12] + ":" + name
            if mode == "120000":
                findings.append(Finding(label, 0, "unsupported-file-type"))
            findings.extend(Finding(label, f.line, f.rule) for f in scan_bytes(name, git(root, "cat-file", "blob", oid)))
    return findings, len(checked)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="also inspect all reachable commits and blobs")
    options = parser.parse_args(argv)
    try:
        root = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode("utf-8").strip())
        findings, count = working_tree(root)
        history_count = 0
        if options.history:
            older, history_count = history(root)
            findings.extend(older)
    except (OSError, RuntimeError, UnicodeError, ValueError, subprocess.CalledProcessError):
        print("public-source-check: read-failed", file=sys.stderr)
        return 2
    for finding in sorted(set(findings)):
        print(json.dumps({"path": finding.path, "line": finding.line, "rule": finding.rule}, ensure_ascii=True))
    print(f"public-source-check: files={count} history_blobs={history_count} findings={len(set(findings))}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
