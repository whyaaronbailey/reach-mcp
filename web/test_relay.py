"""Local checks for the web relay (no public exposure, no real GitHub sign-in).

1. Proxy path: the relay's FastMCP server (auth disabled, in-memory) lists the
   exposed tools from the running loopback native server and returns images.
2. Auth/guard: the real ASGI app (OAuth on, dummy GitHub credentials) on a test
   port answers OAuth discovery, 401s unauthenticated MCP, and 403s methods/tools
   outside the allowlists before auth.

Requires a running loopback native server matching --config. The check-local.py
wrapper creates isolated dummy credentials and explicitly authorizes observations.
Run with the VM relay environment: web\\.venv\\Scripts\\python.exe web\\test_relay.py
"""
import argparse
import asyncio
import json
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request

import uvicorn
from fastmcp import Client

import relay

TEST_PORT = 8899


def check(label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label}{(' - ' + detail) if detail else ''}")
    return ok


async def proxy_checks(config):
    results = []
    server = relay.build_server(config, auth=False)
    async with Client(server) as c:
        tools = sorted(t.name for t in await c.list_tools())
        results.append(check("proxy lists exactly the exposed tools", set(tools) == relay.EXPOSED_TOOLS,
                             f"{len(tools)} tools"))
        info = await c.call_tool('reach_get_screen_info', {})
        text = info.content[0].text
        results.append(check("proxied read tool works", '"monitors"' in text))
        shot = await c.call_tool('reach_screenshot', {"max_long_edge": 600})
        kinds = [b.type for b in shot.content]
        results.append(check("proxied screenshot returns an image", "image" in kinds, str(kinds)))
        # Each proxied call is a fresh upstream session; coordinate mapping needs the
        # native server to remember the screenshot across them.
        after = json.loads((await c.call_tool('reach_get_screen_info', {})).content[0].text)
        last = after.get("last_screenshot") or {}
        results.append(check("screenshot state persists across proxied calls",
                             last.get("image_width") == 600 or last.get("image_height") == 600,
                             f"last={last.get('image_width')}x{last.get('image_height')}"))
    return all(results)


def post(path, body, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{TEST_PORT}{path}", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream",
                                          "Host": f"127.0.0.1:{TEST_PORT}", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def get(path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{TEST_PORT}{path}", timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def auth_checks(config):
    cfg = dict(config, client_id="dummy-client-id", client_secret="dummy-client-secret")
    relay.PORT = TEST_PORT
    app = relay.create_app(cfg)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=TEST_PORT, log_level="error", access_log=False))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    results = []
    try:
        s, b = get("/.well-known/oauth-protected-resource/mcp")
        results.append(check("protected-resource metadata served", s == 200, f"{s}"))
        s, b = get("/.well-known/oauth-authorization-server")
        meta = json.loads(b) if s == 200 else {}
        results.append(check("authorization-server metadata points at public URL",
                             str(meta.get("issuer", "")).startswith(cfg["public_url"]), meta.get("issuer", s)))
        results.append(check("OAuth discovery advertises S256 PKCE",
                             "S256" in meta.get("code_challenge_methods_supported", [])))
        discovery = json.dumps({"jsonrpc": "2.0", "id": 10, "method": "server/discover"}).encode()
        s, _ = post("/mcp", discovery)
        results.append(check("unauthenticated server/discover -> 401", s == 401, str(s)))
        from urllib.parse import urlsplit
        registration_path = urlsplit(meta["registration_endpoint"]).path
        registration = json.dumps({
            "client_name": "local-compatibility-check",
            "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }).encode()
        s, b = post(registration_path, registration)
        registered = json.loads(b) if s == 201 else {}
        results.append(check("ChatGPT redirect dynamic registration works",
                             s == 201 and bool(registered.get("client_id")), str(s)))
        s, _ = post("/mcp", b"")
        results.append(check("empty POST -> 401", s == 401, str(s)))
        init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                      "clientInfo": {"name": "t", "version": "0"}}}).encode()
        s, _ = post("/mcp", init)
        results.append(check("unauthenticated initialize -> 401", s == 401, str(s)))
        s, _ = post("/mcp", init, {"Authorization": "Bearer not-a-real-token"})
        results.append(check("bogus bearer -> 401", s == 401, str(s)))
        bad = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "resources/list"}).encode()
        s, _ = post("/mcp", bad)
        results.append(check("non-allowlisted method -> 403 before auth", s == 403, str(s)))
        badtool = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                              "params": {"name": "run_shell", "arguments": {}}}).encode()
        s, _ = post("/mcp", badtool)
        results.append(check("unknown tool -> 403 before auth", s == 403, str(s)))
        s, _ = post("/mcp", b"[{}]")
        results.append(check("JSON batch -> 400", s == 400, str(s)))
        click = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": 'reach_click', "arguments": {"x": 1, "y": 1}}}).encode()
        s, _ = post("/mcp", click)
        results.append(check("allowlisted action tool without auth -> 401 (not executed)", s == 401, str(s)))
    finally:
        server.should_exit = True
        t.join(timeout=5)
    return all(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=relay.CONFIG,
                        help="Relay configuration to test; prefer check-local.py for isolated dummy credentials.")
    args = parser.parse_args()
    config = relay.load_config(args.config)
    ok = asyncio.run(proxy_checks(config))
    ok = auth_checks(config) and ok
    print("ALL PASS" if ok else "SOME CHECKS FAILED")
    raise SystemExit(0 if ok else 1)
