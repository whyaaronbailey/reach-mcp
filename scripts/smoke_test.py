"""End-to-end check over a real stdio MCP connection, as any agent would connect.

    python scripts/smoke_test.py              # read-only: tool list, screen info, screenshot, windows
    python scripts/smoke_test.py --interactive

--interactive briefly takes over the desktop: opens a new Notepad window, types
Unicode text, copies it back through the clipboard, verifies it, then closes
only its test document. Clipboard restoration is attempted while the connection remains available.

The server starts in Ask mode. Pass --approve-test-calls only when deliberately
authorizing this isolated smoke test; it uses the normal local owner API.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from test_controls import select_test_mode

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / ".venv" / "Scripts" / "python.exe"
SAMPLE = "Hello from reach-mcp — Unicode ✓ café 日本語 🚀"


def text_of(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "type", "") == "text")


async def call(session: ClientSession, name: str, args: dict | None = None):
    print(f"START {name}", flush=True)
    result = await session.call_tool(name, args or {})
    print(f"DONE {name}", flush=True)
    if getattr(result, "is_error", False) or getattr(result, "isError", False):
        raise RuntimeError(f"{name} failed: {text_of(result)}")
    return result


async def run_smoke(interactive: bool, approve_test_calls: bool, state_dir: Path) -> int:
    env = os.environ.copy()
    env.pop("REACH_MCP_CONFIG", None)
    env.pop("REACH_MCP_TOKEN", None)
    env["REACH_MCP_HOME"] = str(state_dir.parent)
    params = StdioServerParameters(
        command=str(PY),
        args=["-m", "reach_mcp", "--client", "smoke-test",
              "--control-port", "0", "--control-state-dir", str(state_dir)],
        cwd=str(ROOT), env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=90.0) as session:
            init = await session.initialize()
            if approve_test_calls:
                await asyncio.to_thread(select_test_mode, state_dir, "full", 300)
                print("Authorized this isolated smoke server for 300 seconds.", flush=True)
            else:
                print("Manual approvals required. Open the isolated panel locally:", flush=True)
                print(f"scripts/open-controls.ps1 -StateDirectory '{state_dir}'", flush=True)
            print(f"server: {init.server_info.name} {init.server_info.version}, protocol {init.protocol_version}")
            tools = (await session.list_tools()).tools
            for t in tools:
                a = t.annotations
                print(f"  {t.name:20} read_only={a.read_only_hint if a else None}")

            info = json.loads(text_of(await call(session, 'reach_get_screen_info')))
            print("monitors:", [(m["index"], m["width"], m["height"], m["primary"]) for m in info["monitors"]],
                  "dpi:", info["dpi_awareness"], "elevated:", info["server_elevated"])

            shot = await call(session, 'reach_screenshot')
            img = next(c for c in shot.content if c.type == "image")
            out = ROOT / "logs" / "smoke-screenshot.png"
            out.parent.mkdir(exist_ok=True)
            out.write_bytes(base64.b64decode(img.data))
            print("screenshot image captured")
            print("saved", out, out.stat().st_size, "bytes")

            wins = json.loads(text_of(await call(session, 'reach_list_windows')))
            print(f"windows: {len(wins)} visible")

            if not interactive:
                return 0

            import uuid
            doc_path = ROOT / "logs" / f"smoke-input-{uuid.uuid4().hex[:10]}.txt"
            doc_path.write_text("", encoding="utf-8")
            saved_clip = text_of(await call(session, 'reach_get_clipboard'))
            await call(session, 'reach_launch_application', {
                "target": "notepad.exe", "arguments": f'"{doc_path}"'})
            new = []
            for _ in range(40):
                await call(session, 'reach_wait', {"seconds": 0.25})
                new = [w for w in json.loads(text_of(await call(
                    session, 'reach_list_windows', {"process": "notepad.exe"})))
                    if doc_path.stem in w["title"]]
                if new:
                    break
            if len(new) != 1:
                raise RuntimeError("Unique test document did not appear in Notepad")
            pad = new[0]
            try:
                await call(session, 'reach_focus_window', {"hwnd": pad["hwnd"]})
                await call(session, 'reach_screenshot', {"hwnd": pad["hwnd"], "max_long_edge": 800})
                state = json.loads(text_of(await call(session, 'reach_get_screen_info')))
                foreground = state["foreground_window"] or {}
                if foreground.get("hwnd") != pad["hwnd"] or doc_path.stem not in foreground.get("title", ""):
                    raise RuntimeError("Test document is not foreground; aborting before typing")
                meta = state["last_screenshot"]
                await call(session, 'reach_click', {"x": meta["image_width"] // 2, "y": meta["image_height"] // 2})
                await call(session, 'reach_type_text', {"text": SAMPLE})
                await call(session, 'reach_wait', {"seconds": 1.0})
                await call(session, 'reach_press_keys', {"keys": "ctrl+a"})
                await call(session, 'reach_wait', {"seconds": 0.5})
                await call(session, 'reach_press_keys', {"keys": "ctrl+c"})
                await call(session, 'reach_wait', {"seconds": 1.0})
                got = text_of(await call(session, 'reach_get_clipboard'))
                ok = got == SAMPLE
                print("round-trip:", "OK" if ok else "MISMATCH (contents redacted)", flush=True)
                after = await call(session, 'reach_screenshot', {"hwnd": pad["hwnd"], "max_long_edge": 800})
                img = next(c for c in after.content if c.type == "image")
                (ROOT / "logs" / "smoke-notepad.png").write_bytes(base64.b64decode(img.data))
                await call(session, 'reach_press_keys', {"keys": "ctrl+s"})
                await call(session, 'reach_wait', {"seconds": 0.5})
                saved_ok = doc_path.read_text(encoding="utf-8-sig") == SAMPLE
                print("saved-file:", "OK" if saved_ok else "MISMATCH", flush=True)
                ok = ok and saved_ok
            finally:
                # Win11 Notepad can share a process; close only the test document.
                foreground = json.loads(text_of(await call(session, 'reach_get_screen_info')))["foreground_window"] or {}
                if foreground.get("hwnd") == pad["hwnd"] and doc_path.stem in foreground.get("title", ""):
                    await call(session, 'reach_press_keys', {"keys": "ctrl+s"})
                    await call(session, 'reach_press_keys', {"keys": "ctrl+w"})
                await call(session, 'reach_set_clipboard', {"text": saved_clip})
            return 0 if ok else 1


async def main(interactive: bool, approve_test_calls: bool = False) -> int:
    with tempfile.TemporaryDirectory(prefix="reach-smoke-test-") as directory:
        return await run_smoke(interactive, approve_test_calls, Path(directory) / ".state")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--interactive", action="store_true")
    ap.add_argument(
        "--approve-test-calls", action="store_true",
        help="Explicitly authorize this isolated test server for 300 seconds through its owner API.",
    )
    args = ap.parse_args()
    sys.exit(asyncio.run(main(args.interactive, args.approve_test_calls)))
