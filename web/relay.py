"""Reach MCP: an owner-only GitHub OAuth relay for remote chat clients.

Only the explicit desktop tool allowlist is proxied. The native server and
relay both listen on loopback; only the authenticated relay may be published.
Native approval, audit and kill switches remain in force.
"""
from __future__ import annotations

import json
import sys
import ipaddress
from urllib.parse import urlsplit
from pathlib import Path

# pythonw (no console): keep diagnostics local; no access/header/body logging.
if __name__ == "__main__":
    _log_root = Path(__file__).resolve().parent
    sys.stdout = (_log_root / "stdout.log").open("a", encoding="utf-8", buffering=1)
    sys.stderr = (_log_root / "stderr.log").open("a", encoding="utf-8", buffering=1)

import uvicorn
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.github import GitHubProvider, GitHubTokenVerifier
from fastmcp.server.providers.base import Provider
from fastmcp.server.providers.proxy import ProxyProvider
from starlette.responses import JSONResponse

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "secrets" / "github-oauth.json"
HOST = "127.0.0.1"
PORT = 8891

# Listed explicitly so a new native tool is never published by accident.
EXPOSED_TOOLS = frozenset({
    'reach_get_screen_info', 'reach_screenshot', 'reach_list_windows', 'reach_get_cursor_position',
    'reach_get_clipboard', 'reach_wait', 'reach_focus_window', 'reach_move_mouse', 'reach_click', 'reach_drag',
    'reach_scroll', 'reach_type_text', 'reach_press_keys', 'reach_set_clipboard', 'reach_launch_application',
})
# server/discover is the modern-MCP handshake (successor to initialize; metadata only).
METHODS = frozenset({"initialize", "server/discover", "notifications/initialized", "ping",
                     "tools/list", "tools/call"})
RELAY_INSTRUCTIONS = (
    "Control the authenticated owner's Windows desktop using observe, act, verify. "
    "Follow the connected client's permission controls. reach_get_screen_info reports "
    "approval_policy and desktop availability. Under client policy no VM-local approval "
    "is required. Request local approval only if the server explicitly reports a local "
    "approval failure. A locked, disconnected, or secure Windows desktop requires the "
    "user to restore the Windows session; opening approval controls cannot fix it. "
    "An interrupted action may be partial: inspect the target before retrying input. "
    "Never unlock Windows, enter passwords, or approve your own requests."
)
MAX_BODY = 262144
CLIENT_REDIRECTS = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/connector/oauth/*",
    "http://localhost:*/*",
    "http://127.0.0.1:*/*",
]


def native_client_factory(native_url, token):
    def factory():
        return Client(StreamableHttpTransport(native_url, headers={"Authorization": f"Bearer {token}"}),
                      timeout=120, init_timeout=15)
    return factory


class ExposedProvider(Provider):
    """Keep the native server's schemas/results; publish only EXPOSED_TOOLS."""
    def __init__(self, factory):
        super().__init__()
        self.native = ProxyProvider(factory)

    async def _list_tools(self):
        return [tool for tool in await self.native.list_tools() if tool.name in EXPOSED_TOOLS]

    async def _get_tool(self, name, version=None):
        if name not in EXPOSED_TOOLS:
            return None
        return await self.native.get_tool(name, version)


class OwnerOnlyVerifier(GitHubTokenVerifier):
    """GitHub accepts any account; admit only the owner's immutable numeric ID.

    Runs on every MCP request, so a token for any other GitHub account is
    rejected before the relay touches the local server.
    """
    def __init__(self, allowed_ids, **kwargs):
        super().__init__(**kwargs)
        self.allowed_ids = frozenset(str(i) for i in allowed_ids)

    async def verify_token(self, token):
        result = await super().verify_token(token)
        if result is None or result.subject not in self.allowed_ids:
            return None
        return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


class MethodGuard:
    """Enforce MCP method/tool allowlists on /mcp BEFORE auth or upstream.

    OAuth discovery/registration/authorize/token/callback routes pass through to
    FastMCP's OAuth proxy unchanged.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/mcp":
            return await self.app(scope, receive, send)

        async def reject(status, reason):
            await JSONResponse({"error": reason}, status_code=status,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)

        if scope["method"] not in {"POST", "GET", "DELETE"}:
            return await reject(405, "Method not allowed")
        if scope["method"] != "POST":
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY:
                return await reject(413, "Request too large")
            if not message.get("more_body", False):
                break
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        # ChatGPT probes with an empty POST; let auth answer it (401 + resource
        # metadata). An empty body names no method, so nothing can execute.
        if not body:
            return await self.app(scope, replay, send)
        try:
            data = json.loads(body, object_pairs_hook=unique_object)
            if not isinstance(data, dict):
                raise ValueError("Object required; JSON-RPC batches are not supported")
        except (ValueError, UnicodeError):
            print(f"guard: rejected non-object or invalid JSON body ({len(body)} bytes)", file=sys.stderr)
            return await reject(400, "A single unambiguous JSON object is required")
        rpc_method = data.get("method")
        if not isinstance(rpc_method, str) or rpc_method not in METHODS:
            print(f"guard: rejected MCP method {str(rpc_method)[:64]!r}", file=sys.stderr)
            return await reject(403, "MCP method allowlist denied this request")
        if rpc_method == "tools/call":
            params = data.get("params")
            if (not isinstance(params, dict) or not isinstance(params.get("name"), str)
                    or params["name"] not in EXPOSED_TOOLS):
                print("guard: rejected MCP tool call", file=sys.stderr)
                return await reject(403, "MCP tool allowlist denied this request")
            if "arguments" in params and not isinstance(params["arguments"], dict):
                return await reject(400, "Tool arguments must be an object")
        await self.app(scope, replay, send)


def validate_config(config):
    config = dict(config)
    for key in ("public_url", "client_id", "client_secret", "jwt_signing_key", "native_token"):
        if not isinstance(config.get(key), str) or not config[key] or config[key].startswith("PASTE"):
            raise ValueError(f"Relay configuration: {key} is not set")
    ids = config.get("allowed_github_user_ids")
    if not isinstance(ids, list) or len(ids) != 1 or type(ids[0]) is not int or ids[0] <= 0:
        raise ValueError("Exactly one positive immutable GitHub owner ID is required")
    public = urlsplit(config["public_url"])
    if (public.scheme != "https" or not public.hostname or public.username or public.password
            or public.path not in ("", "/") or public.query or public.fragment):
        raise ValueError("public_url must be an HTTPS origin without credentials or a path")
    if public.port is not None and not 1 <= public.port <= 65535:
        raise ValueError("Invalid public port")
    config["public_url"] = config["public_url"].rstrip("/")
    config.setdefault("native_url", "http://127.0.0.1:8765/mcp")
    native = urlsplit(config["native_url"])
    try:
        loopback = native.hostname == "localhost" or ipaddress.ip_address(native.hostname).is_loopback
    except (ValueError, TypeError):
        loopback = False
    if (native.scheme != "http" or not loopback or native.username or native.password
            or native.path != "/mcp" or native.query or native.fragment
            or native.port is None or not 1 <= native.port <= 65535):
        raise ValueError("native_url must use loopback HTTP with an explicit port and /mcp")
    if len(config["native_token"]) < 24 or len(config["jwt_signing_key"]) < 32:
        raise ValueError("Native and session signing secrets are too short")
    return config


def load_config(path=CONFIG):
    return validate_config(json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object))


def build_server(config, auth=True):
    config = validate_config(config)
    provider = ExposedProvider(native_client_factory(config["native_url"], config["native_token"]))
    if not auth:  # local tests of the proxy path only; never served
        return FastMCP("Reach MCP", providers=[provider], instructions=RELAY_INSTRUCTIONS, mask_error_details=True)
    github = GitHubProvider(
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        base_url=config["public_url"],
        required_scopes=["read:user"],
        allowed_client_redirect_uris=CLIENT_REDIRECTS,
        jwt_signing_key=config["jwt_signing_key"],
        require_authorization_consent=True,
        cache_ttl_seconds=300,
    )
    github._token_validator = OwnerOnlyVerifier(
        config["allowed_github_user_ids"], required_scopes=["read:user"], cache_ttl_seconds=300)
    return FastMCP("Reach MCP", providers=[provider], auth=github, instructions=RELAY_INSTRUCTIONS, mask_error_details=True)


def create_app(config):
    server = build_server(config)
    public_host = config["public_url"].split("://", 1)[1].split("/", 1)[0]
    app = server.http_app(path="/mcp", stateless_http=True, json_response=True,
                          allowed_hosts=[public_host, public_host.split(":")[0], HOST, f"{HOST}:{PORT}"],
                          # Funnel terminates TLS, so requests arrive as http; trust the
                          # public https origin for the OAuth consent form only.
                          allowed_origins=[config["public_url"]],
                          host_origin_protection="auto")
    return MethodGuard(app)


if __name__ == "__main__":
    uvicorn.run(create_app(load_config()), host=HOST, port=PORT, proxy_headers=False,
                access_log=False, log_level="warning", timeout_keep_alive=10,
                limit_concurrency=8)
