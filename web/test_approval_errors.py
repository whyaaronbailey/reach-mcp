"""Real native-SDK -> FastMCP relay error tests, using synthetic desktop data only."""
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport

import relay

ROOT = Path(__file__).resolve().parents[1]
DUMMY_CONFIG = {
    "public_url": "https://reach.example.test",
    "client_id": "dummy-client-id",
    "client_secret": "dummy-client-secret",
    "jwt_signing_key": "dummy-signing-key-for-isolated-test-only",
    "native_token": "dummy-bearer-token-for-isolated-test-only",
    "native_url": "http://127.0.0.1:18765/mcp",
    "allowed_github_user_ids": [12345678],
}
# This child uses the real native SDK and approval wrapper, but replaces the first
# screen-info adapter. It neither reads the desktop nor uses production credentials.
NATIVE_FIXTURE = r"""
from pathlib import Path
import sys
from reach_mcp.approval import ApprovalGate
from reach_mcp.config import Config
from reach_mcp import server as native

def fail():
    raise RuntimeError("synthetic-private-stack-trace")

native.windows.foreground = fail
gate = ApprovalGate(timeout=0.1)
if sys.argv[1] in {"crash", "success"}:
    gate.set_mode("low_risk")
if sys.argv[1] == "success":
    native.windows.foreground = lambda: None
    native.screen.monitors = lambda: []
    native.screen.virtual_screen = lambda: (0, 0, 640, 480)
    native.winput.cursor_pos = lambda: (20, 30)
    native.dpi_mode = lambda: "synthetic"
    native._is_admin = lambda: False
cfg = Config()
cfg.audit.path = Path(sys.argv[2]) / "audit.jsonl"
cfg.safety.pause_file = Path(sys.argv[2]) / "PAUSED"
native.build_server(cfg, "isolated-error-test", gate).run(transport="stdio")
"""


class ApprovalErrorTests(unittest.TestCase):
    def run_proxy_call(self, scenario):
        async def run(directory, script):
            def factory():
                return Client(
                    PythonStdioTransport(
                        script,
                        args=[scenario, directory],
                        python_cmd=str(ROOT / ".venv/Scripts/python.exe"),
                        cwd=str(ROOT),
                        env={"PYTHONPATH": str(ROOT / "src")},
                    ),
                    timeout=15,
                )

            with patch.object(relay, "native_client_factory", return_value=factory):
                server = relay.build_server(DUMMY_CONFIG, auth=False)
            async with Client(server) as client:
                tools = await client.list_tools()
                self.assertIn("reach_get_screen_info", {tool.name for tool in tools})
                return await client.call_tool(
                    "reach_get_screen_info", {}, raise_on_error=False
                )

        with tempfile.TemporaryDirectory(prefix="reach-error-test-") as directory:
            script = Path(directory) / "native_fixture.py"
            script.write_text(NATIVE_FIXTURE, encoding="utf-8")
            return asyncio.run(run(directory, script))

    def test_native_approval_timeout_survives_relay(self):
        result = self.run_proxy_call("timeout")
        self.assertTrue(result.is_error)
        text = "\n".join(block.text for block in result.content if block.type == "text")
        self.assertIn("Reach MCP approval timed out", text)
        self.assertIn("the tool was not executed", text)
        self.assertIn("local Reach MCP approval controls", text)
        self.assertIn("Chat client approval does not replace the local approval", text)
        self.assertNotIn("synthetic-private", text)

    def test_actual_screen_info_handler_result_survives_relay(self):
        result = self.run_proxy_call("success")
        self.assertFalse(result.is_error)
        text = "\n".join(block.text for block in result.content if block.type == "text")
        info = json.loads(text)
        self.assertEqual(info["virtual_screen"], {
            "left": 0, "top": 0, "width": 640, "height": 480,
        })
        self.assertEqual(info["cursor"], [20, 30])
        self.assertEqual(info["monitors"], [])
        self.assertIsNone(info["foreground_window"])
        self.assertFalse(info["server_elevated"])

    def test_native_unexpected_exception_stays_masked_through_relay(self):
        result = self.run_proxy_call("crash")
        self.assertTrue(result.is_error)
        text = "\n".join(block.text for block in result.content if block.type == "text")
        self.assertEqual(text, "Error executing tool reach_get_screen_info")
        self.assertNotIn("synthetic-private", text)


if __name__ == "__main__":
    unittest.main()
