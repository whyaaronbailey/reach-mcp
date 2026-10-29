"""VM-neutral, outbound-only Windows worker for pinned Reach MCP 0.3.0.

The transport credential identifies one enrolled machine/account. It is NOT a
desktop lease. Every native dispatch requires a separately approved, short lease.
No request bodies, tokens, screenshots, command output or exception text are logged.
"""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import sys
import time
import uuid
from urllib.parse import urlsplit

from channel import ChannelDenied, MAX_RESULT, MAX_REQUEST, catalog_digest, encoded, loads, validate_request

BINDING_FIELDS = ("vm_id", "instance_id", "session_id", "connection_id", "gateway_epoch", "control_id")
ROOT = Path(__file__).resolve().parent
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43,128}")
ID_RE = re.compile(r"[0-9a-f]{32}")
VM_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
PACKET_FIELDS = {"version", *BINDING_FIELDS, "machine_uuid", "account_sid", "lease_id", "job_id",
                 "deadline", "lease_expires_at", "control_expires_at", "approval_policy", "method", "params"}


def bounded_json(path, maximum=262144):
    if path.is_symlink() or path.stat().st_size > maximum:
        raise ChannelDenied()
    return loads(path.read_bytes(), maximum)


def load_config(root=ROOT):
    value = bounded_json(root / "worker.json", 8192)
    expected = {"version", "vm_id", "machine_uuid", "account_sid", "gateway", "ca_sha256",
                "manifest_sha256", "workspace", "native_home"}
    if type(value) is not dict or set(value) != expected or value["version"] != 2:
        raise ChannelDenied()
    if not isinstance(value["vm_id"], str) or not VM_RE.fullmatch(value["vm_id"]):
        raise ChannelDenied()
    if str(uuid.UUID(value["machine_uuid"])) != value["machine_uuid"]:
        raise ChannelDenied()
    if not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", value["account_sid"]):
        raise ChannelDenied()
    for key in ("ca_sha256", "manifest_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise ChannelDenied()
    validate_gateway(value["gateway"])
    for key in ("workspace", "native_home"):
        path = Path(value[key])
        if not path.is_absolute() or not path.is_dir() or path.is_symlink():
            raise ChannelDenied()
    manifest_path = root / "native-package.json"
    if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != value["manifest_sha256"]:
        raise ChannelDenied()
    manifest = bounded_json(manifest_path)
    if manifest.get("version") != 2 or manifest.get("native_version") != "0.3.0":
        raise ChannelDenied()
    profile = bounded_json(root / "gateway-profile.json", 8192)
    if (profile.get("version") != 2 or profile.get("oauth_route") is not False or
            profile.get("transport") != "private-outbound-tls" or value["gateway"] not in profile.get("gateways", [])):
        raise ChannelDenied()
    for name, digest in manifest["files"].items():
        if Path(name).name != name or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ChannelDenied()
        path = root / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ChannelDenied()
    verify_runtime(root, manifest)
    return value


def verify_runtime(root, manifest):
    """Check the complete vendored tree; interpreter is preverified by installer."""
    if manifest.get("runtime_kind") != "cpython-embedded-vendored":
        raise ChannelDenied()
    index = bounded_json(root / "runtime-files.json", 4194304)
    if (index.get("version") != 1 or index.get("runtime_kind") != "cpython-embedded-vendored" or
            index.get("python_version") != "3.12.10" or
            index.get("python_artifact", {}).get("sha256") != "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"):
        raise ChannelDenied()
    files = index.get("files", {})
    if not isinstance(files, dict) or not files or len(files) > 12000:
        raise ChannelDenied()
    runtime = root / "runtime"
    actual = set()
    for path in runtime.rglob("*"):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ChannelDenied()
        if path.is_file():
            actual.add(path.relative_to(runtime).as_posix())
    if actual != set(files):
        raise ChannelDenied()
    total = 0
    for name, entry in files.items():
        if (not re.fullmatch(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*", name) or
                any(p in {".", ".."} or p.endswith(".") or re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p) for p in name.split("/")) or
                not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) or
                type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= 33554432):
            raise ChannelDenied()
        path = runtime / name
        total += entry["bytes"]
        if (total > 268435456 or path.stat().st_size != entry["bytes"] or
                hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]):
            raise ChannelDenied()


def validate_gateway(value):
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password or
            url.path not in ("", "/") or url.query or url.fragment):
        raise ChannelDenied()
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ChannelDenied()
    return url


def windows_identity():
    if sys.platform != "win32":
        raise ChannelDenied()
    import win32api
    import win32security
    import win32com.client
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
        # Reject administrators even when UAC merely gives the process a filtered token.
        standard = all(win32security.ConvertSidToStringSid(g[0]) != "S-1-5-32-544" for g in groups)
        statistics = win32security.GetTokenInformation(token, win32security.TokenStatistics)
        logon = str(statistics["AuthenticationId"])
        session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
    finally:
        token.Close()
    values = list(win32com.client.GetObject(r"winmgmts:root\cimv2").ExecQuery("SELECT UUID FROM Win32_ComputerSystemProduct"))
    if len(values) != 1:
        raise ChannelDenied()
    return {"machine_uuid": str(values[0].UUID).lower(), "account_sid": sid,
            "session_id": str(session) + ":" + logon, "session_number": session, "standard": standard}


def identity_check(config):
    current = windows_identity()
    if not current["standard"] or not current["session_number"]:
        raise ChannelDenied()
    if any(current[k] != config[k] for k in ("machine_uuid", "account_sid")):
        raise ChannelDenied()
    executable = Path(sys.executable).resolve()
    if executable not in {(ROOT / "runtime/python.exe").resolve(), (ROOT / "runtime/pythonw.exe").resolve()}:
        raise ChannelDenied()
    return current


def desktop_state(config, identity):
    """Observe the caller's session; never unlock, sign in or switch sessions."""
    if (Path(config["native_home"]) / "PAUSED").exists():
        return "paused"
    try:
        import win32ts
        state = win32ts.WTSQuerySessionInformation(None, identity["session_number"], win32ts.WTSConnectState)
        if state != win32ts.WTSActive:
            return "disconnected"
        user32 = ctypes.windll.user32
        user32.OpenInputDesktop.restype = ctypes.c_void_p
        handle = user32.OpenInputDesktop(0, False, 0x0001)  # DESKTOP_READOBJECTS
        if not handle:
            return "locked"
        try:
            needed = ctypes.c_ulong()
            name = ctypes.create_unicode_buffer(256)
            user32.GetUserObjectInformationW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                                         ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
            if not user32.GetUserObjectInformationW(handle, 2, name, ctypes.sizeof(name), ctypes.byref(needed)):
                return "unavailable"
            return "ready" if name.value.lower() == "default" else "locked"
        finally:
            user32.CloseDesktop.argtypes = [ctypes.c_void_p]
            user32.CloseDesktop(handle)
    except Exception:
        return "unavailable"


def load_credential(root=ROOT):
    import win32crypt
    path = root / "credential.dpapi"
    if path.is_symlink() or path.stat().st_size > 16384:
        raise ChannelDenied()
    raw = win32crypt.CryptUnprotectData(path.read_bytes(), None, None, None, 0)[1]
    value = loads(raw, 4096)
    if (type(value) is not dict or set(value) != {"version", "vm_id", "worker_token", "credential_id"} or
            value["version"] != 2 or not TOKEN_RE.fullmatch(value["worker_token"]) or
            not ID_RE.fullmatch(value["credential_id"])):
        raise ChannelDenied()
    return value


class ReplayGuard:
    """Durably claim a job BEFORE dispatch. Ambiguous jobs are never executed again."""
    def __init__(self, path):
        self.db = sqlite3.connect(str(path))
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, claimed INTEGER NOT NULL)")
        self.db.commit()

    def accept(self, packet, config, binding, now=None):
        now = time.time() if now is None else now
        if type(packet) is not dict or set(packet) != PACKET_FIELDS or packet["version"] != 2:
            raise ChannelDenied()
        for name in BINDING_FIELDS:
            if packet[name] != binding[name]:
                raise ChannelDenied()
        if any(packet[key] != config[key] for key in ("machine_uuid", "account_sid")):
            raise ChannelDenied()
        if any(not isinstance(packet[key], str) or not ID_RE.fullmatch(packet[key]) for key in ("job_id", "lease_id", "control_id")):
            raise ChannelDenied()
        if packet["approval_policy"] != "client" or packet["method"] != "tools/call":
            raise ChannelDenied()
        if (type(packet["deadline"]) is not int or type(packet["lease_expires_at"]) is not int or
                type(packet["control_expires_at"]) is not int or
                not now < packet["deadline"] <= min(now + 95, packet["lease_expires_at"], packet["control_expires_at"]) or
                packet["control_expires_at"] > packet["lease_expires_at"]):
            raise ChannelDenied()
        validate_request(packet["method"], packet["params"])
        try:
            with self.db:
                # Old jobs cannot pass a fresh deadline; retain 1 day for defense in depth.
                self.db.execute("DELETE FROM jobs WHERE claimed < ?", (int(now) - 86400,))
                self.db.execute("INSERT INTO jobs VALUES (?, ?)", (packet["job_id"], int(now)))
        except sqlite3.IntegrityError:
            raise ChannelDenied() from None

    def close(self):
        self.db.close()


def redact_transport_credential(value, token):
    """Remove this worker's literal credential from bounded JSON results.

    This is accidental plaintext-leak protection, not a sandbox against a
    same-user command that can encode data or decrypt its own DPAPI material.
    """
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise ChannelDenied()
    raw = encoded(value, MAX_RESULT)
    return loads(raw.replace(token.encode("ascii"), b"[REDACTED_WORKER_CREDENTIAL]"), MAX_RESULT)


class Transport:
    def __init__(self, config, token, root=ROOT):
        ca = root / "gateway-ca.crt"
        if ca.is_symlink() or hashlib.sha256(ca.read_bytes()).hexdigest() != config["ca_sha256"]:
            raise ChannelDenied()
        self.url = validate_gateway(config["gateway"])
        self.context = ssl.create_default_context(cafile=str(ca))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.token = token

    def request(self, path, value):
        if path not in {"/worker/enroll", "/worker/connect", "/worker/next", "/worker/result", "/worker/revoke", "/worker/heartbeat"}:
            raise ChannelDenied()
        connection = http.client.HTTPSConnection(self.url.hostname, self.url.port or 443, context=self.context, timeout=3 if path == "/worker/heartbeat" else 30)
        try:
            body = encoded(redact_transport_credential(value, self.token) if path == "/worker/result" else value, MAX_RESULT)
            connection.request("POST", path, body=body,
                               headers={"Authorization": "Bearer " + self.token,
                                        "Content-Type": "application/json", "Cache-Control": "no-store"})
            response = connection.getresponse()
            raw = response.read(MAX_RESULT + 1)
            if len(raw) > MAX_RESULT or response.status not in {200, 204}:
                raise ChannelDenied()
            return None if response.status == 204 else loads(raw, MAX_RESULT)
        finally:
            connection.close()


def write_status(config, state, connected=False):
    value = {"version": 2, "vm_id": config["vm_id"], "observed_at": int(time.time()),
             "desktop_state": state, "transport_connected": connected,
             "enrollment_is_desktop_authority": False}
    target = ROOT / "state/status.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    os.replace(temporary, target)


def desired_control(response, config, now=None):
    """A reservation is usable only inside its independently approved owner lease."""
    now = time.time() if now is None else now
    if (type(response) is not dict or response.get("version") != 2 or
            response.get("vm_id") != config["vm_id"] or "control" not in response):
        raise ChannelDenied()
    control = response["control"]
    if control is None:
        return None
    lease = response.get("lease")
    if (type(control) is not dict or set(control) != {"control_id", "lease_id", "expires_at"} or
            any(not isinstance(control[k], str) or not ID_RE.fullmatch(control[k])
                for k in ("control_id", "lease_id")) or
            type(control["expires_at"]) is not int or type(lease) is not dict or
            lease.get("lease_id") != control["lease_id"] or type(lease.get("expires_at")) is not int or
            not now < control["expires_at"] <= lease["expires_at"]):
        raise ChannelDenied()
    return dict(control)


def require_same_control(response, config, authority):
    control = desired_control(response, config)
    if (control is None or control["control_id"] != authority["control_id"] or
            control["lease_id"] != authority["lease_id"]):
        raise ChannelDenied()
    authority["expires_at"] = control["expires_at"]


def current_desktop(config, binding):
    current = identity_check(config)
    if current["session_id"] != binding["session_id"]:
        raise ChannelDenied()
    return desktop_state(config, current)


async def run_session(config, credential, instance_id):
    identity = identity_check(config)
    transport = Transport(config, credential["worker_token"])
    binding = {"version": 2, "vm_id": config["vm_id"], "instance_id": instance_id,
               "session_id": identity["session_id"], "control_id": None}
    # Reaching this connect means any previous native stdio context has fully
    # exited. Only now may the server accept the null teardown acknowledgment.
    hello = await asyncio.to_thread(transport.request, "/worker/connect",
                {**binding, "control_protocol": 1, "machine_uuid": config["machine_uuid"],
                 "account_sid": config["account_sid"], "desktop_state": desktop_state(config, identity)})
    control = desired_control(hello, config)
    for key in ("connection_id", "gateway_epoch"):
        if not isinstance(hello.get(key), str) or not ID_RE.fullmatch(hello[key]):
            raise ChannelDenied()
        binding[key] = hello[key]
    while control is None:
        state = current_desktop(config, binding)
        write_status(config, state, True)
        # Idle workers maintain transport liveness without starting a native
        # desktop server or retaining another agent's background processes.
        await asyncio.sleep(1)
        response = await asyncio.to_thread(transport.request, "/worker/heartbeat",
                                          {**binding, "desktop_state": state})
        control = desired_control(response, config)
    binding["control_id"] = control["control_id"]
    await run_native_context(config, transport, binding, control)


async def run_native_context(config, transport, binding, control):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    if current_desktop(config, binding) != "ready":
        raise ChannelDenied()
    environment = {k: v for k, v in os.environ.items() if not k.startswith("REACH_")}
    environment["REACH_MCP_HOME"] = config["native_home"]
    environment["REACH_GATEWAY_JOB_NAME"] = "Local\\ReachGateway-" + binding["control_id"]
    parameters = StdioServerParameters(command=str(ROOT / "runtime/python.exe"),
        args=["-I", "-B", str(ROOT / "native_worker.py"), "--native-server", "--config", str(ROOT / "config.toml"),
              "--client", "reach-gateway-" + config["vm_id"], "--approval-policy", "client"],
        cwd=config["workspace"], env=environment)
    replay = ReplayGuard(ROOT / "state/jobs.sqlite")
    authority = dict(control)
    error_log = open(os.devnull, "w")
    job = None
    teardown_uncertain = False
    try:
        job, _ = create_context_job(binding["control_id"])
        async with stdio_client(parameters, errlog=error_log) as (reader, writer):
            try:
                async with ClientSession(reader, writer, read_timeout_seconds=90) as native:
                    await native.initialize()
                    actual = (await native.list_tools()).model_dump(by_alias=True, exclude_none=True)
                    if catalog_digest(actual) != catalog_digest(bounded_json(ROOT / "tool-catalog.json")):
                        raise ChannelDenied()
                    assert_context_job_active(job)
                    state = current_desktop(config, binding)
                    if state != "ready":
                        raise ChannelDenied()
                    # A new holder is acknowledged only after a fresh native
                    # context has started and its exact pinned catalog is verified.
                    response = await asyncio.to_thread(transport.request, "/worker/heartbeat",
                                                      {**binding, "desktop_state": state})
                    require_same_control(response, config, authority)
                    async def jobs():
                        while True:
                            state = current_desktop(config, binding)
                            write_status(config, state, True)
                            if state != "ready":
                                raise ChannelDenied()
                            packet = await asyncio.to_thread(transport.request, "/worker/next",
                                                             {**binding, "desktop_state": state})
                            if packet is None:
                                await asyncio.sleep(1)
                                continue
                            replay.accept(packet, config, binding)
                            if (packet["lease_id"] != authority["lease_id"] or
                                    packet["control_id"] != authority["control_id"]):
                                raise ChannelDenied()
                            response = {**binding, "lease_id": packet["lease_id"], "job_id": packet["job_id"],
                                        "result": None, "failed": True}
                            try:
                                if current_desktop(config, binding) != "ready":
                                    raise ChannelDenied()
                                deadline = min(packet["deadline"], packet["control_expires_at"], authority["expires_at"])
                                if deadline <= time.time():
                                    raise ChannelDenied()
                                async with asyncio.timeout(deadline - time.time()):
                                    result = await native.call_tool(packet["params"]["name"], packet["params"]["arguments"])
                                response["result"] = result.model_dump(by_alias=True, exclude_none=True)
                                response["failed"] = False
                                encoded(response, MAX_RESULT)
                            except Exception:
                                response["result"] = None
                                response["failed"] = True
                            # A failed/uncertain transport never resubmits this job.
                            await asyncio.to_thread(transport.request, "/worker/result", response)
                    async def heartbeat():
                        while True:
                            await asyncio.sleep(2)
                            state = current_desktop(config, binding)
                            response = await asyncio.to_thread(transport.request, "/worker/heartbeat",
                                                              {**binding, "desktop_state": state})
                            require_same_control(response, config, authority)
                            if state != "ready":
                                raise ChannelDenied()
                    async with asyncio.TaskGroup() as group:
                        group.create_task(jobs())
                        group.create_task(heartbeat())
            finally:
                active_job, job = job, None
                try:
                    stop_context_job(active_job)
                except BaseException:
                    teardown_uncertain = True
                    raise
    finally:
        # No null/new-holder acknowledgment is sent until stdio exit and
        # confirmed termination of the parent-owned native process tree.
        cleanup_failed = teardown_uncertain
        try:
            if job is not None:
                stop_context_job(job)
        except BaseException:
            cleanup_failed = True
        for close in (replay.close, error_log.close):
            try:
                close()
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            raise TeardownUncertain() from None


def enroll(config):
    """Installer runs elevated, token arrives on stdin; only DPAPI ciphertext persists."""
    import win32crypt
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ChannelDenied()
    token = sys.stdin.buffer.read(4097).decode("ascii").strip()
    if not TOKEN_RE.fullmatch(token):
        raise ChannelDenied()
    credential = Transport(config, token).request("/worker/enroll",
                 {k: config[k] for k in ("version", "vm_id", "machine_uuid", "account_sid")})
    if (credential.get("version") != 2 or credential.get("vm_id") != config["vm_id"] or
            not TOKEN_RE.fullmatch(credential.get("worker_token", "")) or
            not ID_RE.fullmatch(credential.get("credential_id", ""))):
        raise ChannelDenied()
    destination = ROOT / "credential.dpapi"
    if destination.exists():
        raise ChannelDenied()
    ciphertext = win32crypt.CryptProtectData(encoded(credential, 4096), "Reach worker transport", None, None, None, 4)
    with destination.open("xb") as output:
        output.write(ciphertext)
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({"enrolled": True, "vm_id": config["vm_id"], "desktop_lease_granted": False}))


async def main():
    config = load_config()
    identity_check(config)
    credential = load_credential()
    if credential["vm_id"] != config["vm_id"]:
        raise ChannelDenied()
    instance_id = uuid.uuid4().hex  # Stable for this process, fenced across process restarts.
    while True:
        try:
            await run_session(config, credential, instance_id)
        except Exception:
            write_status(config, "unavailable", False)
            await asyncio.sleep(5)


class TeardownUncertain(BaseException):
    """Never reconnect/acknowledge another holder after uncertain process cleanup."""


def create_context_job(control_id):
    import win32api
    import win32job
    if not isinstance(control_id, str) or not ID_RE.fullmatch(control_id):
        raise ChannelDenied()
    name = "Local\\ReachGateway-" + control_id
    job = win32job.CreateJobObject(None, name)
    try:
        if win32api.GetLastError() == 183:  # Refuse a pre-existing same-user named object.
            raise ChannelDenied()
        info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
        return job, name
    except Exception:
        job.Close()
        raise


def join_context_job():
    import win32api
    import win32job
    name = os.environ.pop("REACH_GATEWAY_JOB_NAME", "")
    if not re.fullmatch(r"Local\\ReachGateway-[0-9a-f]{32}", name):
        raise ChannelDenied()
    job = win32job.OpenJobObject(win32job.JOB_OBJECT_ASSIGN_PROCESS, False, name)
    try:
        win32job.AssignProcessToJobObject(job, win32api.GetCurrentProcess())
    finally:
        # Parent is the only handle owner. Its failure kills this process tree.
        job.Close()


def assert_context_job_active(job):
    import win32job
    info = win32job.QueryInformationJobObject(job, win32job.JobObjectBasicAccountingInformation)
    if info["ActiveProcesses"] < 1:
        raise ChannelDenied()


def stop_context_job(job):
    import win32job
    failed = False
    try:
        win32job.TerminateJobObject(job, 1)
        deadline = time.monotonic() + 5
        while win32job.QueryInformationJobObject(job, win32job.JobObjectBasicAccountingInformation)["ActiveProcesses"]:
            if time.monotonic() >= deadline:
                failed = True
                break
            time.sleep(.02)
    except Exception:
        failed = True
    try:
        job.Close()
    except Exception:
        failed = True
    if failed:
        # A Close error must not mask uncertainty with a reconnectable Exception.
        raise TeardownUncertain() from None


def native_job():
    """Return a non-inheritable kill-on-close job for this native process tree."""
    import win32api
    import win32job
    job = win32job.CreateJobObject(None, '')
    try:
        info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
        win32job.AssignProcessToJobObject(job, win32api.GetCurrentProcess())
        return job
    except Exception:
        job.Close()
        raise


def native_server():
    """One Windows job owns native Reach and every command child, never legacy Reach."""
    import runpy
    identity_check(load_config())
    join_context_job()
    sys.argv = ["reach_mcp", *sys.argv[2:]]
    runpy.run_module("reach_mcp", run_name="__main__")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--native-server"]:
        native_server()
        raise SystemExit(0)
    parser = argparse.ArgumentParser()
    parser.add_argument("--enroll", action="store_true")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    try:
        if args.enroll:
            enroll(load_config())
        elif args.revoke:
            config = load_config()
            credential = load_credential()
            if credential["vm_id"] != config["vm_id"]:
                raise ChannelDenied()
            print(json.dumps(Transport(config, credential["worker_token"]).request("/worker/revoke",
                             {"version": 2, "vm_id": config["vm_id"]})))
        else:
            asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except BaseException:
        # Fixed diagnostics only, including a grouped teardown-uncertainty error. Detailed transport/native errors can contain secrets.
        print("Reach worker validation or connectivity failed.", file=sys.stderr)
        raise SystemExit(1)
