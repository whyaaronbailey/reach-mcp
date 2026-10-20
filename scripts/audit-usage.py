#!/usr/bin/env python3
"""Read Codex quota metadata without creating a thread or starting a model turn."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

SCHEMA_VERSION = 1
MAX_JSON_BYTES = 1024 * 1024
NEXT_STEPS = {
    "codex_cli_not_found": "Use the usage dashboard, or pass --codex with an already installed Codex executable. Nothing was installed.",
    "invalid_cli_path": "Pass --codex with an existing Codex executable, using a path without shell metacharacters.",
    "collector_failed": "Check that the existing Codex CLI is usable and already signed in to the intended ChatGPT account. No login was started.",
    "collector_timeout": "Check the existing CLI sign-in and network, then retry or use the usage dashboard.",
    "quota_read_failed": "Check the existing CLI sign-in and selected account, or use the usage dashboard. No login was started.",
    "unsupported_quota_response": "Use the usage dashboard or an existing compatible Codex CLI. Missing data is not zero usage.",
    "invalid_sample": "Compare two successful JSON samples from this script.",
    "output_file_exists": "Choose a new output filename. Existing files are never overwritten.",
    "output_write_failed": "Choose an existing writable parent directory and a new output filename.",
}


class AuditError(Exception):
    """Only fixed, non-sensitive error codes may leave the collector."""

    def __init__(self, code: str):
        self.code = code


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def unavailable(code: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "captured_at": timestamp(),
        "status": "unavailable",
        "reason": code,
        "next_step": NEXT_STEPS[code],
    }


def finite_number(value, minimum: float, maximum: float | None = None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        if not math.isfinite(value) or value < minimum:
            return None
    except OverflowError:
        return None
    return value if maximum is None or value <= maximum else None


def window(value):
    if not isinstance(value, dict):
        return None
    duration = finite_number(value.get("windowDurationMins"), 1)
    reset = finite_number(value.get("resetsAt"), 0)
    return {
        "used_percent": finite_number(value.get("usedPercent"), 0, 100),
        "window_duration_minutes": duration,
        "resets_at": reset,
    }


def limits(result: dict) -> dict:
    source = result.get("rateLimitsByLimitId")
    if not isinstance(source, dict) or not source:
        legacy = result.get("rateLimits")
        if not isinstance(legacy, dict):
            raise AuditError("unsupported_quota_response")
        source = {legacy.get("limitId") or "legacy": legacy}
    clean = {}
    for key, value in source.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", key):
            continue
        if not isinstance(value, dict):
            continue
        clean[key] = {"primary": window(value.get("primary")),
                      "secondary": window(value.get("secondary"))}
    if not clean or not any(w and w["used_percent"] is not None
                            for b in clean.values() for w in b.values()):
        raise AuditError("unsupported_quota_response")
    return clean


def cli_command(explicit: str | None):
    executable = explicit or shutil.which("codex") or shutil.which("codex.exe")
    if not executable:
        raise AuditError("codex_cli_not_found")
    path = Path(executable).expanduser().resolve()
    if not path.is_file():
        raise AuditError("invalid_cli_path")
    if os.name == "nt" and path.suffix.lower() in {".cmd", ".bat"}:
        # Node-based CLI installations may expose a .cmd shim. Only this fixed
        # command is allowed; reject characters that cmd.exe could interpret.
        if any(c in str(path) for c in '"&|<>^%!\r\n'):
            raise AuditError("invalid_cli_path")
        command_processor = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
        return f'"{command_processor}" /d /s /c ""{path}" app-server"'
    return [str(path), "app-server"]


def stop_process(proc):
    if proc is None:
        return
    try:
        proc.stdin.close()
    except (OSError, ValueError, AttributeError):
        pass
    try:
        proc.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    # Scope cleanup strictly to the collector process tree, never other agents.
    try:
        if os.name == "nt":
            subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5, check=False)
        else:
            os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=2)
    except (OSError, subprocess.SubprocessError):
        try:
            proc.kill()
            proc.wait(timeout=2)
        except (OSError, subprocess.SubprocessError):
            pass


def snapshot(executable: str | None, timeout: float) -> dict:
    command = cli_command(executable)
    proc = None
    messages = queue.Queue(maxsize=128)
    deadline = time.monotonic() + timeout

    def read_output():
        try:
            while True:
                line = proc.stdout.readline(MAX_JSON_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_JSON_BYTES:
                    messages.put_nowait(None)
                    return
                try:
                    message = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if isinstance(message, dict):
                    messages.put_nowait(message)
        except (OSError, ValueError, queue.Full):
            pass
        try:
            messages.put_nowait(None)
        except queue.Full:
            pass

    def send(message):
        proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        proc.stdin.flush()

    def receive(request_id):
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AuditError("collector_timeout")
            try:
                message = messages.get(timeout=remaining)
            except queue.Empty:
                raise AuditError("collector_timeout") from None
            if message is None:
                raise AuditError("collector_failed")
            if message.get("id") == request_id:
                if "error" in message or not isinstance(message.get("result"), dict):
                    raise AuditError("quota_read_failed")
                return message["result"]

    try:
        kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
        proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace",
                                shell=False, **kwargs)
        threading.Thread(target=read_output, daemon=True).start()
        send({"id": 0, "method": "initialize", "params": {
            "clientInfo": {"name": "reach_usage_audit",
                           "title": "Reach MCP usage audit", "version": "1.0"}}})
        receive(0)
        send({"method": "initialized", "params": {}})
        send({"id": 1, "method": "account/rateLimits/read", "params": {}})
        result = receive(1)
        return {"schema_version": SCHEMA_VERSION, "captured_at": timestamp(),
                "status": "ok", "rate_limits": limits(result)}
    except AuditError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError):
        raise AuditError("collector_failed") from None
    finally:
        stop_process(proc)


def load_sample(path: str) -> dict:
    try:
        with open(path, "rb") as source:
            raw = source.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError
        value = json.loads(raw)
        if (value.get("schema_version") != SCHEMA_VERSION or value.get("status") != "ok"
                or not isinstance(value.get("rate_limits"), dict)):
            raise ValueError
        captured = dt.datetime.fromisoformat(value["captured_at"])
        if captured.utcoffset() is None:
            raise ValueError
        value["captured_at"] = captured.astimezone(dt.timezone.utc).isoformat(timespec="seconds")
        for key, bucket in value["rate_limits"].items():
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", key) or not isinstance(bucket, dict):
                raise ValueError
            for name in ("primary", "secondary"):
                w = bucket.get(name)
                if w is not None and (not isinstance(w, dict) or any(
                    w.get(field) is not None and finite_number(w[field], low, high) is None
                    for field, low, high in (("used_percent", 0, 100),
                                            ("window_duration_minutes", 1, None),
                                            ("resets_at", 0, None)))):
                    raise ValueError
        return value
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise AuditError("invalid_sample") from None


def compare(before: dict, after: dict, quiet: bool) -> dict:
    warnings = [
        "This is an aggregate account meter; other Work/Codex sessions, subagents, scheduled tasks and devices can affect it.",
        "Percentages may be coarse and reporting may be delayed. No observed increase is not proof of exactly zero usage.",
        "Reach logs prove tool execution, not which OpenAI allowance was charged.",
    ]
    if not quiet:
        warnings.append("A quiet test window has not been confirmed; attribution is inconclusive.")
    keys = sorted(set(before["rate_limits"]) | set(after["rate_limits"]))
    observations = {}
    for key in keys:
        observations[key] = {}
        for name in ("primary", "secondary"):
            b = before["rate_limits"].get(key, {}).get(name)
            a = after["rate_limits"].get(key, {}).get(name)
            if b is None and a is None:
                continue
            outcome, delta = "incomparable", None
            if b and a and all(b.get(k) is not None and a.get(k) is not None for k in
                              ("used_percent", "resets_at", "window_duration_minutes")):
                if any(b[k] != a[k] for k in ("resets_at", "window_duration_minutes")):
                    outcome = "window_changed"
                else:
                    delta = a["used_percent"] - b["used_percent"]
                    outcome = ("usage_increased" if delta > 0 else
                               "usage_decreased" if delta < 0 else "no_observed_change")
            observations[key][name] = {"outcome": outcome, "delta_percentage_points": delta}
    outcomes = [w["outcome"] for b in observations.values() for w in b.values()]
    if dt.datetime.fromisoformat(after["captured_at"]) < dt.datetime.fromisoformat(before["captured_at"]):
        warnings.append("The after sample predates the before sample.")
        status = "inconclusive"
    elif not quiet or not outcomes or any(o in {"incomparable", "window_changed", "usage_decreased"} for o in outcomes):
        status = "inconclusive"
    else:
        status = "observed_increase" if "usage_increased" in outcomes else "no_observed_increase"
    return {"schema_version": SCHEMA_VERSION, "captured_at": timestamp(),
            "status": status, "before_captured_at": before["captured_at"],
            "after_captured_at": after["captured_at"],
            "quiet_window_confirmed_by_operator": quiet,
            "observations": observations, "warnings": warnings}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    snap = commands.add_parser("snapshot", help="Read quota metadata; never starts a model turn.")
    snap.add_argument("--codex", help="Existing Codex executable; defaults to PATH.")
    snap.add_argument("--timeout", type=float, default=30)
    snap.add_argument("--output", help="Save a sanitized JSON sample; refuse to overwrite.")
    diff = commands.add_parser("compare", help="Compare two saved, sanitized samples.")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--quiet-window-confirmed", action="store_true",
                      help="Attest that no other Work/Codex activity occurred.")
    args = parser.parse_args(argv)
    try:
        if args.operation == "snapshot":
            if not math.isfinite(args.timeout) or not 1 <= args.timeout <= 120:
                parser.error("--timeout must be between 1 and 120 seconds")
            if args.output and Path(args.output).exists():
                raise AuditError("output_file_exists")
            result = snapshot(args.codex, args.timeout)
            if args.output:
                try:
                    with open(args.output, "x", encoding="utf-8") as output:
                        output.write(json.dumps(result, indent=2) + "\n")
                except FileExistsError:
                    raise AuditError("output_file_exists") from None
                except OSError:
                    raise AuditError("output_write_failed") from None
        else:
            result = compare(load_sample(args.before), load_sample(args.after),
                             args.quiet_window_confirmed)
    except AuditError as exc:
        result = unavailable(exc.code)
    except (OSError, ValueError, TypeError, OverflowError, RuntimeError):
        result = unavailable("collector_failed")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 2 if result["status"] == "unavailable" else 0


if __name__ == "__main__":
    raise SystemExit(main())
