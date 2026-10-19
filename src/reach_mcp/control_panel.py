"""Loopback owner controls. This is separate from the MCP tool surface.

The random capability URL is stored in an owner-restricted local directory.
This is an accidental-use control, not isolation from code running as the owner.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import threading
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route
import uvicorn

from .approval import ApprovalError, ApprovalGate
from .audit import AuditLog

MAX_BODY = 4096


def secure_state_directory(path: Path) -> None:
    """Set an exact owner/SYSTEM/Administrators DACL before writing capabilities."""
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError("Control state directory must not be a symlink")
    if os.name != "nt":
        path.chmod(0o700)
        return
    # PowerShell arguments are passed as data through the environment, never code.
    script = (
        "$ErrorActionPreference='Stop';$stage='inspect';try{"
        "$p=$env:REACH_MCP_STATE_DIR;"
        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;"
        "$allowed=@($sid.Value,'S-1-5-18','S-1-5-32-544');"
        "$current=Get-Acl -LiteralPath $p;"
        "$rules=@($current.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));"
        "$owner=$current.GetOwner([Security.Principal.SecurityIdentifier]).Value;"
        "$valid=$current.AreAccessRulesProtected -and $owner -eq $sid.Value -and $rules.Count -eq 3;"
        "foreach($rule in $rules){"
        "$ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;"
        "if($ruleSid -notin $allowed -or $rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or "
        "$rule.FileSystemRights -ne 'FullControl' -or $rule.InheritanceFlags -ne 'ContainerInherit, ObjectInherit'){$valid=$false}};"
        "if($valid){exit 0};"
        "$stage='apply';$acl=New-Object Security.AccessControl.DirectorySecurity;"
        "$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);"
        "foreach($s in @($sid.Value,'S-1-5-18','S-1-5-32-544')){"
        "$id=New-Object Security.Principal.SecurityIdentifier($s);"
        "$r=New-Object Security.AccessControl.FileSystemAccessRule("
        "$id,'FullControl','ContainerInherit,ObjectInherit','None','Allow');"
        "$acl.AddAccessRule($r)};"
        "Set-Acl -LiteralPath $p -AclObject $acl"
        "}catch{[Console]::Error.WriteLine('REACH_ACL_ERROR '+$stage+' '+$_.Exception.GetType().FullName+' '+($_.FullyQualifiedErrorId -replace '[^A-Za-z0-9_.,:+-]','_'));exit 1}"
    )
    # Python launched by PowerShell 7 inherits its incompatible module paths.
    # Let Windows PowerShell rebuild its own default path instead.
    env = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    env["REACH_MCP_STATE_DIR"] = str(path.resolve())
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    try:
        subprocess.run(
            [str(executable), "-NoProfile", "-NonInteractive", "-Command", script],
            env=env, check=True, timeout=15, capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except subprocess.CalledProcessError as exc:
        # Do not expose raw subprocess output, command text, paths, or environment.
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace")
        match = re.search(r"REACH_ACL_ERROR ([A-Za-z_]+) ([A-Za-z0-9_.+]+) ([A-Za-z0-9_.,:+-]+)", stderr)
        detail = f"stage={match[1]}, type={match[2]}, error={match[3]}" if match else f"exit={exc.returncode}"
        raise RuntimeError(f"Unable to restrict control state directory ACLs ({detail}).") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Unable to restrict control state directory ACLs (helper timed out).") from None
    except OSError:
        raise RuntimeError("Unable to restrict control state directory ACLs (Windows PowerShell could not start).") from None


class ControlPanel:
    """Authenticated local HTTP panel sharing a native server's approval gate."""

    def __init__(self, gate: ApprovalGate, state_dir: Path, *, port: int = 0,
                 audit: AuditLog | None = None):
        self.gate = gate
        self.state_dir = state_dir
        self.port = port
        self.audit = audit
        self.token = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(24)
        self.origin = ""
        self.url_file = state_dir / f"control-panel-{os.getpid()}.url"
        self._server = None
        self._thread = None
        self._socket = None

    def _record(self, event: str, args: dict) -> None:
        if self.audit:
            self.audit.record(event, args, True, time.monotonic())

    def create_app(self):
        async def page(request: Request):
            template = Path(__file__).with_name("control_panel.html").read_text(encoding="utf-8")
            return HTMLResponse(template.replace("CSP_NONCE", self.nonce))

        async def health(request: Request):
            return JSONResponse({"status": "ok", "pid": os.getpid()})

        async def state(request: Request):
            return JSONResponse(self.gate.snapshot())

        async def command(request: Request):
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    return JSONResponse({"error": "Request too large"}, status_code=413)
            try:
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise ValueError("Object required")
                if request.url.path == "/api/mode":
                    if set(data) != {"mode", "duration"}:
                        raise ValueError("Expected mode and duration")
                    self.gate.set_mode(data["mode"], data["duration"])
                    self._record("approval_mode", data)
                else:
                    if set(data) != {"id", "allow"} or type(data["allow"]) is not bool:
                        raise ValueError("Expected request ID and boolean allow")
                    if not isinstance(data["id"], str) or len(data["id"]) > 128:
                        raise ValueError("Invalid request ID")
                    if not self.gate.decide(data["id"], data["allow"]):
                        return JSONResponse({"error": "Request expired or already decided"}, status_code=409)
                    self._record("approval_decision", data)
            except ApprovalError as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            except (ValueError, TypeError):
                return JSONResponse({"error": "Invalid control request"}, status_code=400)
            return JSONResponse(self.gate.snapshot())

        app = Starlette(routes=[
            Route("/", page),
            Route("/health", health),
            Route("/api/state", state),
            Route("/api/mode", command, methods=["POST"]),
            Route("/api/decision", command, methods=["POST"]),
        ])
        panel = self

        class Guard:
            async def __call__(self, scope, receive, send):
                if scope["type"] != "http":
                    return await app(scope, receive, send)
                headers = {}
                duplicate = False
                for key, value in scope.get("headers", []):
                    if key in {b"host", b"authorization", b"origin"} and key in headers:
                        duplicate = True
                    headers[key] = value
                expected_host = panel.origin.removeprefix("http://").encode()
                origin = headers.get(b"origin")
                error = None
                if duplicate or headers.get(b"host") != expected_host or scope.get("query_string"):
                    error = (403, "Invalid local request")
                elif origin is not None and origin != panel.origin.encode():
                    error = (403, "Origin denied")
                elif scope["path"].startswith("/api/"):
                    if not hmac.compare_digest(
                        headers.get(b"authorization", b""),
                        f"Bearer {panel.token}".encode(),
                    ):
                        error = (401, "Owner capability required")
                    elif scope["method"] == "POST" and origin != panel.origin.encode():
                        error = (403, "Origin required")
                    elif scope["method"] == "POST" and headers.get(b"content-type", b"").split(b";")[0] != b"application/json":
                        error = (415, "JSON required")
                async def secured_send(message):
                    if message["type"] == "http.response.start":
                        message["headers"] = list(message.get("headers", [])) + [
                            (b"cache-control", b"no-store"),
                            (b"referrer-policy", b"no-referrer"),
                            (b"x-content-type-options", b"nosniff"),
                            (b"x-frame-options", b"DENY"),
                            (b"content-security-policy", (
                                "default-src 'none'; connect-src 'self'; "
                                f"script-src 'nonce-{panel.nonce}'; style-src 'nonce-{panel.nonce}'; "
                                "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
                            ).encode()),
                        ]
                    await send(message)
                if error:
                    return await JSONResponse({"error": error[1]}, status_code=error[0])(scope, receive, secured_send)
                await app(scope, receive, secured_send)

        return Guard()

    def start(self) -> None:
        secure_state_directory(self.state_dir)
        self._socket = socket.socket()
        self._socket.bind(("127.0.0.1", self.port))
        self.port = self._socket.getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self._socket.listen(32)
        self._server = uvicorn.Server(uvicorn.Config(
            self.create_app(), host="127.0.0.1", port=self.port,
            access_log=False, log_config=None, log_level="warning",
            lifespan="off", proxy_headers=False, limit_concurrency=16,
            timeout_keep_alive=3,
        ))
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [self._socket]}, daemon=True,
            name="owner-controls",
        )
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if not self._thread.is_alive() or time.monotonic() >= deadline:
                self.stop()
                raise RuntimeError("Owner controls could not start")
            time.sleep(0.02)
        try:
            # Never print this URL: its fragment is a local owner capability.
            self.url_file.write_text(f"{self.origin}/#{self.token}\n", encoding="utf-8")
            if os.name != "nt":
                self.url_file.chmod(0o600)
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        self.gate.close()
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5)
        if self._socket:
            self._socket.close()
        self.url_file.unlink(missing_ok=True)
