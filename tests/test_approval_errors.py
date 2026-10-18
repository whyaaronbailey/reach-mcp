"""Exercise the real MCP SDK error boundary without accessing the desktop."""
import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from reach_mcp.approval import ApprovalError, ApprovalGate
from reach_mcp.config import Config
from reach_mcp import server as native


def make_server(tmp_path, gate):
    cfg = Config()
    cfg.audit.path = tmp_path / "audit.jsonl"
    cfg.safety.pause_file = tmp_path / "PAUSED"
    return native.build_server(cfg, "error-regression", gate), cfg


async def pending(gate):
    for _ in range(200):
        requests = gate.snapshot()["pending"]
        if requests:
            return requests[0]
        await asyncio.sleep(0.005)
    raise AssertionError("No approval request appeared")


@pytest.mark.parametrize("outcome", ["timeout", "denied"])
def test_screen_info_empty_arguments_returns_actionable_approval_error(
    monkeypatch, tmp_path, outcome
):
    async def run():
        gate = ApprovalGate(timeout=0.1 if outcome == "timeout" else 10)
        server, cfg = make_server(tmp_path, gate)
        touched = []

        def forbidden():
            touched.append(True)
            raise AssertionError("The desktop must not be read without approval")

        monkeypatch.setattr(native.windows, "foreground", forbidden)
        task = asyncio.create_task(server.call_tool("reach_get_screen_info", {}))
        request = await pending(gate)
        assert request["arguments"] == {}
        if outcome == "denied":
            assert gate.decide(request["id"], False)
        with pytest.raises(ToolError) as caught:
            await task
        assert not isinstance(caught.value, UnexpectedToolError)
        message = str(caught.value)
        assert "the tool was not executed" in message
        assert ("timed out" if outcome == "timeout" else "denied") in message
        if outcome == "timeout":
            assert "local Reach MCP approval controls" in message
            assert "Chat client approval does not replace the local approval" in message
        assert not touched
        assert gate.snapshot()["mode"] == "ask"
        assert gate.snapshot()["pending"] == []
        rows = [json.loads(row) for row in cfg.audit.path.read_text().splitlines()]
        assert len(rows) == 1
        assert rows[0]["args"] == {} and not rows[0]["ok"]
        assert rows[0]["detail"].startswith("ApprovalError:")
    asyncio.run(run())


def test_unknown_approval_details_do_not_cross_mcp_boundary(monkeypatch, tmp_path):
    class FailingGate(ApprovalGate):
        async def authorize(self, *args, **kwargs):
            raise ApprovalError("synthetic-private-value C:/private/config.json")

    async def run():
        server, _ = make_server(tmp_path, FailingGate())
        with pytest.raises(ToolError) as caught:
            await server.call_tool("reach_get_screen_info", {})
        assert "Approval was not granted" in str(caught.value)
        assert "synthetic-private" not in str(caught.value)
        assert "private/config" not in str(caught.value)
    asyncio.run(run())


def test_unexpected_handler_exception_still_masked(monkeypatch, tmp_path):
    async def run():
        gate = ApprovalGate()
        server, _ = make_server(tmp_path, gate)

        def fail():
            raise RuntimeError("synthetic-private-stack-trace")

        monkeypatch.setattr(native.windows, "foreground", fail)
        task = asyncio.create_task(server.call_tool("reach_get_screen_info", {}))
        request = await pending(gate)
        assert gate.decide(request["id"], True)
        with pytest.raises(UnexpectedToolError) as caught:
            await task
        assert str(caught.value) == "Error executing tool reach_get_screen_info"
        assert "synthetic-private" not in str(caught.value)
        assert gate.snapshot()["mode"] == "ask"
    asyncio.run(run())
