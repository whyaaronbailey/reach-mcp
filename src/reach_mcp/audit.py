"""Append-only JSONL record of every tool call."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Argument names whose values may contain secrets the user typed or copied.
TEXT_ARGS = {"text", "arguments", "target"}
# Developer tools never store payloads, even when legacy typed-text logging is on.
PRIVATE_ARGS = {"content", "patch", "old", "new", "command", "stdin", "env",
                "path", "source", "destination", "cwd", "query", "glob",
                "expected_sha256", "allowed_roots", "workspace"}

def private_summary(value):
    encoded = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
    length = len(value) if isinstance(value, (str, list, dict)) else len(encoded)
    return {"chars": length, "sha256": hashlib.sha256(encoded).hexdigest()[:16]}



class AuditLog:
    def __init__(self, path: Path, enabled: bool = True, log_text: bool = False, client: str = ""):
        self.path = path
        self.enabled = enabled
        self.log_text = log_text
        self.client = client
        self._lock = threading.Lock()
        if enabled:
            path.parent.mkdir(parents=True, exist_ok=True)

    def _sanitize(self, args: dict) -> dict:
        def clean(value, key=""):
            if key.lower() in PRIVATE_ARGS or any(part in key.lower() for part in
                    ("secret", "password", "token", "authorization", "cookie")):
                return private_summary(value)
            if key in TEXT_ARGS and not self.log_text:
                return private_summary(value)
            if isinstance(value, dict):
                return {k: clean(v, str(k)) for k, v in value.items()}
            if isinstance(value, list):
                return [clean(v) for v in value]
            return value
        return clean(args)

    def record(self, tool: str, args: dict, ok: bool, started: float, detail: str = "") -> None:
        if not self.enabled:
            return
        sanitized = self._sanitize(args)
        if tool == "reach_write_process" and "text" in args:
            sanitized["text"] = private_summary(args["text"])
        entry = {
            "event_id": uuid.uuid4().hex,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "pid": os.getpid(),
            "client": self.client,
            "tool": tool,
            "args": sanitized,
            "ok": ok,
            "ms": round((time.monotonic() - started) * 1000),
        }
        if detail:
            entry["detail"] = detail[:500]
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
