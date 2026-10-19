"""Entry point: ``reach-mcp [--transport stdio|http] [--config PATH]``.

stdio is what local agents (Claude Code, Codex, OpenCode, ChatGPT desktop
plugins) launch. http serves Streamable HTTP on loopback only, behind a bearer
token, for clients that prefer connecting to a running server.
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import os
import sys
from pathlib import Path

from .win.dpi import make_process_dpi_aware


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class BearerAuth:
    """Minimal ASGI middleware: every request must carry ``Authorization: Bearer <token>``."""

    def __init__(self, app, token: str):
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            supplied = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self.expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self.app(scope, receive, send)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="reach-mcp")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--config", help="TOML config path (default: config.toml in the project root)")
    parser.add_argument("--host", help="HTTP bind address (loopback only)")
    parser.add_argument("--port", type=int, help="HTTP port")
    parser.add_argument("--client", default="", help="label recorded in the audit log, e.g. 'codex'")
    parser.add_argument("--approval-policy", choices=("local", "client"), default="local",
                        help="Approval authority: local owner panel (default), or connected client permissions")
    parser.add_argument("--control-port", type=int, help="Loopback owner control port (HTTP: 8766; stdio: automatic)")
    parser.add_argument("--control-state-dir", type=Path, help="Private directory for the local owner capability file")
    args = parser.parse_args(argv)

    # Before anything touches screens or windows.
    make_process_dpi_aware()

    from . import config
    from .server import build_server, _is_admin

    if _is_admin():
        sys.exit('Run Reach MCP as the normal non-elevated desktop user.')

    cfg = config.load(args.config)
    host = args.host or cfg.http.host
    port = args.port or cfg.http.port
    token = os.environ.get(cfg.http.token_env, "")
    if args.transport == "http":
        if not _is_loopback(host):
            sys.exit(f"refusing to bind {host}: the HTTP transport is loopback-only")
        if len(token) < 24:
            sys.exit(f"set {cfg.http.token_env} to a random token of at least 24 characters")
    control_port = args.control_port if args.control_port is not None else (8766 if args.transport == "http" else 0)
    if not 0 <= control_port <= 65535:
        parser.error("--control-port must be between 0 and 65535")

    from .approval import ApprovalGate
    from .audit import AuditLog
    from .control_panel import ControlPanel

    gate = ApprovalGate(policy=args.approval_policy)
    panel = ControlPanel(
        gate, args.control_state_dir or config.PROJECT_ROOT / ".state",
        port=control_port,
        audit=AuditLog(cfg.audit.path, cfg.audit.enabled, False, "owner-controls"),
    )
    try:
        panel.start()
        server = build_server(cfg, client_label=args.client or args.transport, approval_gate=gate)
        if args.transport == "stdio":
            server.run("stdio")
        else:
            import uvicorn
            app = BearerAuth(server.streamable_http_app(host=host), token)
            uvicorn.run(app, host=host, port=port, log_level="warning",
                        log_config=None, access_log=False, proxy_headers=False)
    finally:
        panel.stop()


if __name__ == "__main__":
    main()
