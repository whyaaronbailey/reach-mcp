"""Append-only JSONL record of every tool call."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Argument names whose values may contain secrets the user typed or copied.
TEXT_ARGS = {"text", "arguments", "target"}


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
        out = {}
        for k, v in args.items():
            if k in TEXT_ARGS and isinstance(v, str) and not self.log_text:
                out[k] = {"chars": len(v), "sha256": hashlib.sha256(v.encode()).hexdigest()[:16]}
            else:
                out[k] = v
        return out

    def record(self, tool: str, args: dict, ok: bool, started: float, detail: str = "") -> None:
        if not self.enabled:
            return
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "pid": os.getpid(),
            "client": self.client,
            "tool": tool,
            "args": self._sanitize(args),
            "ok": ok,
            "ms": round((time.monotonic() - started) * 1000),
        }
        if detail:
            entry["detail"] = detail[:500]
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
