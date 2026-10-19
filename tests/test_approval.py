"""Approval tests never read the desktop or inject real input."""
import asyncio
import json
import threading

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from reach_mcp.approval import ApprovalError, ApprovalGate, LOW_RISK_TOOLS


async def pending(gate):
    for _ in range(200):
        requests = gate.snapshot()["pending"]
        if requests:
            return requests[0]
        await asyncio.sleep(0.005)
    raise AssertionError("No pending approval appeared")


def test_default_ask_and_one_shot_exact_arguments():
    async def run():
        gate = ApprovalGate()
        args = {"seconds": 0, "screenshot": False}
        task = asyncio.create_task(gate.authorize('reach_wait', args, "test"))
        request = await pending(gate)
        assert gate.snapshot()["mode"] == "ask"
        assert request["arguments"] == args
        assert len(request["id"]) >= 32
        assert gate.decide(request["id"], True)
        assert not gate.decide(request["id"], True)
        grant = await task
        assert gate.snapshot()["pending"] == []
        gate.consume(grant, 'reach_wait', args, "test")
        with pytest.raises(ApprovalError):
            gate.consume(grant, 'reach_wait', args, "test")
    asyncio.run(run())


def test_arguments_are_snapshotted_and_grant_bound():
    async def run():
        gate = ApprovalGate()
        args = {"text": "before", "screenshot": False}
        task = asyncio.create_task(gate.authorize('reach_type_text', args, "first"))
        request = await pending(gate)
        args["text"] = "after"
        request["arguments"]["text"] = "panel copy changed"
        assert gate.snapshot()["pending"][0]["arguments"]["text"] == "before"
        assert gate.decide(request["id"], True)
        grant = await task
        with pytest.raises(ApprovalError):
            gate.consume(grant, 'reach_type_text', args, "first")
    asyncio.run(run())


@pytest.mark.parametrize("change", ["tool", "client", 'reach_screenshot'])
def test_grant_cannot_authorize_different_request(change):
    async def run():
        gate = ApprovalGate()
        gate.set_mode("full")
        args = {"seconds": 0, "screenshot": False}
        grant = await gate.authorize('reach_wait', args, "one")
        tool, client = 'reach_wait', "one"
        if change == "tool":
            tool = 'reach_screenshot'
        elif change == "client":
            client = "two"
        else:
            args['reach_screenshot'] = True
        with pytest.raises(ApprovalError):
            gate.consume(grant, tool, args, client)
    asyncio.run(run())


def test_denial_timeout_cancellation_and_close_clean_queue():
    async def run():
        gate = ApprovalGate(timeout=0.1)
        task = asyncio.create_task(gate.authorize('reach_screenshot', {}))
        request = await pending(gate)
        assert gate.decide(request["id"], False)
        with pytest.raises(ApprovalError, match="denied"):
            await task
        assert not gate.snapshot()["pending"]
        with pytest.raises(ApprovalError, match="timed out"):
            await gate.authorize('reach_screenshot', {})
        task = asyncio.create_task(gate.authorize('reach_screenshot', {}))
        request = await pending(gate)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not gate.snapshot()["pending"]
        assert not gate.decide(request["id"], True)
        task = asyncio.create_task(gate.authorize('reach_screenshot', {}))
        await pending(gate)
        gate.close()
        with pytest.raises(ApprovalError, match="closed"):
            await task
        assert not gate.snapshot()["pending"]
        with pytest.raises(ApprovalError):
            await gate.authorize('reach_wait', {})
    asyncio.run(run())


@pytest.mark.parametrize("tool", sorted(LOW_RISK_TOOLS))
def test_low_risk_is_explicit_observation_allowlist(tool):
    async def run():
        gate = ApprovalGate()
        gate.set_mode("low_risk")
        args = {"screenshot": True} if tool == 'reach_wait' else {}
        grant = await gate.authorize(tool, args)
        assert not gate.snapshot()["pending"]
        gate.consume(grant, tool, args)
    asyncio.run(run())


@pytest.mark.parametrize("tool", ['reach_get_clipboard', 'reach_move_mouse', 'reach_press_keys', "ui_snapshot", "unknown"])
def test_low_risk_asks_for_clipboard_input_and_future_tools(tool):
    async def run():
        gate = ApprovalGate()
        gate.set_mode("low_risk")
        task = asyncio.create_task(gate.authorize(tool, {}))
        request = await pending(gate)
        gate.decide(request["id"], False)
        with pytest.raises(ApprovalError):
            await task
    asyncio.run(run())


def test_mode_change_invalidates_pending_and_not_yet_dispatched_grants():
    async def run():
        gate = ApprovalGate()
        task = asyncio.create_task(gate.authorize('reach_click', {}))
        await pending(gate)
        gate.set_mode("full")
        with pytest.raises(ApprovalError, match="changed"):
            await task
        grant = await gate.authorize('reach_click', {})
        gate.set_mode("ask")
        with pytest.raises(ApprovalError):
            gate.consume(grant, 'reach_click', {})
    asyncio.run(run())


def test_temporary_mode_expiry_returns_to_ask_and_cannot_dispatch():
    async def run():
        now = [100.0]
        gate = ApprovalGate(clock=lambda: now[0])
        gate.set_mode("full", duration=10)
        assert gate.snapshot()["expires_at"] is not None
        grant = await gate.authorize('reach_screenshot', {})
        now[0] = 110.0
        assert gate.snapshot()["mode"] == "ask"
        assert gate.snapshot()["expires_at"] is None
        with pytest.raises(ApprovalError):
            gate.consume(grant, 'reach_screenshot', {})
    asyncio.run(run())


def test_queue_is_bounded_and_thread_decision_is_safe():
    async def run():
        gate = ApprovalGate(max_pending=1)
        task = asyncio.create_task(gate.authorize('reach_screenshot', {}))
        request = await pending(gate)
        with pytest.raises(ApprovalError, match="queue is full"):
            await gate.authorize('reach_wait', {})
        thread = threading.Thread(target=gate.decide, args=(request["id"], True))
        thread.start()
        thread.join()
        grant = await task
        gate.consume(grant, 'reach_screenshot', {})
    asyncio.run(run())


@pytest.mark.parametrize("duration", [0, -1, 3601, float("inf"), float("nan"), True])
def test_invalid_mode_durations_are_rejected(duration):
    gate = ApprovalGate()
    with pytest.raises(ValueError):
        gate.set_mode("full", duration)
    assert gate.snapshot()["mode"] == "ask"


def test_invalid_mode_and_decision_do_not_grant():
    gate = ApprovalGate()
    for mode in ("invalid", None, {}, []):
        with pytest.raises(ValueError):
            gate.set_mode(mode)
    assert not gate.decide("invented", True)
    assert not gate.decide("invented", "yes")
    assert gate.snapshot()["mode"] == "ask"


class FakeMCPServer:
    def __init__(self, **kwargs):
        self.functions = {}

    def tool(self, **metadata):
        def register(fn):
            self.functions[metadata["name"]] = fn
            return fn
        return register


def native_fixture(monkeypatch, tmp_path, gate):
    from reach_mcp import server as native
    from reach_mcp.config import Config
    monkeypatch.setattr(native, "MCPServer", FakeMCPServer)
    monkeypatch.setattr(native.desktop, "status", lambda: {
        "available": True, "locked": False, "reason": None,
    })
    cfg = Config()
    cfg.audit.path = tmp_path / "audit.jsonl"
    cfg.safety.pause_file = tmp_path / "PAUSED"
    cfg.safety.action_delay_ms = 0
    return native, cfg, native.build_server(cfg, "test", gate)


def test_native_reads_wait_for_approval_and_denial_audits_once(monkeypatch, tmp_path):
    async def run():
        gate = ApprovalGate()
        native, cfg, server = native_fixture(monkeypatch, tmp_path, gate)
        calls = []
        monkeypatch.setattr(native.clipboard, "get_text", lambda: calls.append("read") or "data")
        task = asyncio.create_task(server.functions['reach_get_clipboard']())
        request = await pending(gate)
        assert not calls
        gate.decide(request["id"], False)
        with pytest.raises(ToolError, match="approval denied"):
            await task
        assert not calls
        rows = [json.loads(row) for row in cfg.audit.path.read_text().splitlines()]
        assert len(rows) == 1 and rows[0]["ok"] is False
        assert rows[0]["args"] == {}
    asyncio.run(run())


def test_native_defaults_bound_and_allow_once_does_not_persist(monkeypatch, tmp_path):
    async def run():
        gate = ApprovalGate()
        _, _, server = native_fixture(monkeypatch, tmp_path, gate)
        task = asyncio.create_task(server.functions['reach_wait'](seconds=0))
        request = await pending(gate)
        assert request["arguments"] == {"seconds": 0, "screenshot": False}
        gate.decide(request["id"], True)
        assert await task == "Waited 0s."
        again = asyncio.create_task(server.functions['reach_wait'](seconds=0))
        request = await pending(gate)
        gate.decide(request["id"], False)
        with pytest.raises(ToolError, match="approval denied"):
            await again
    asyncio.run(run())


@pytest.mark.parametrize("policy", ["local", "client"])
@pytest.mark.parametrize("kill_switch", ["pause", "corner"])
def test_automatic_policies_keep_input_kill_switches(monkeypatch, tmp_path, kill_switch, policy):
    async def run():
        gate = ApprovalGate(policy=policy)
        if policy == "local":
            gate.set_mode("full")
        native, cfg, server = native_fixture(monkeypatch, tmp_path, gate)
        calls = []
        monkeypatch.setattr(native.winput, "move_to", lambda *args: calls.append(args))
        monkeypatch.setattr(native.winput, "cursor_pos", lambda: (0, 0) if kill_switch == "corner" else (20, 20))
        if kill_switch == "pause":
            cfg.safety.pause_file.touch()
        with pytest.raises(native.PolicyError):
            await server.functions['reach_move_mouse'](5, 5, coordinate_space="screen")
        assert not calls
    asyncio.run(run())


def test_default_server_cannot_read_without_panel(monkeypatch, tmp_path):
    async def run():
        native, cfg, _ = native_fixture(monkeypatch, tmp_path, ApprovalGate())
        calls = []
        monkeypatch.setattr(native.clipboard, "get_text", lambda: calls.append("read"))
        server = native.build_server(cfg, "test")
        task = asyncio.create_task(server.functions['reach_get_clipboard']())
        await asyncio.sleep(0.06)
        assert not task.done() and not calls
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not calls
    asyncio.run(run())


TOOL_CALLS = [
    ('reach_get_screen_info', {}), ('reach_screenshot', {}), ('reach_list_windows', {}),
    ('reach_get_cursor_position', {}), ('reach_get_clipboard', {}), ('reach_wait', {"seconds": 0}),
    ('reach_focus_window', {"hwnd": 1}),
    ('reach_move_mouse', {"x": 5, "y": 5, "coordinate_space": "screen"}),
    ('reach_click', {"x": 5, "y": 5, "coordinate_space": "screen"}),
    ('reach_drag', {"start_x": 5, "start_y": 5, "end_x": 10, "end_y": 10, "coordinate_space": "screen"}),
    ('reach_scroll', {"direction": "down"}),
    ('reach_type_text', {"text": "approval test secret"}),
    ('reach_press_keys', {"keys": "enter"}),
    ('reach_set_clipboard', {"text": "approval test secret"}),
    ('reach_launch_application', {"target": "notepad.exe"}),
]


@pytest.mark.parametrize(("tool", "arguments"), TOOL_CALLS)
def test_every_tool_blocks_before_desktop_access_and_cancels_cleanly(monkeypatch, tmp_path, tool, arguments):
    import inspect

    async def run():
        gate = ApprovalGate()
        native, cfg, server = native_fixture(monkeypatch, tmp_path, gate)
        assert set(server.functions) == {name for name, _ in TOOL_CALLS}
        calls = []

        def forbidden(*args, **kwargs):
            calls.append("desktop operation")
            raise AssertionError("Desktop was touched without approval")

        # Replace all Win32 adapter functions, not just the expected body call.
        for module in (native.windows, native.winput, native.clipboard, native.screen):
            for name, value in list(vars(module).items()):
                if inspect.isfunction(value) and value.__module__ == module.__name__:
                    monkeypatch.setattr(module, name, forbidden)
        monkeypatch.setattr(native.os, "startfile", forbidden)
        task = asyncio.create_task(server.functions[tool](**arguments))
        request = await pending(gate)
        assert not task.done() and not calls
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not calls and gate.snapshot()["pending"] == []
        assert not gate.decide(request["id"], True)
        rows = [json.loads(row) for row in cfg.audit.path.read_text().splitlines()]
        assert len(rows) == 1 and rows[0]["ok"] is False and rows[0]["args"] == {}
        assert "approval test secret" not in cfg.audit.path.read_text()
    asyncio.run(run())


@pytest.mark.parametrize("policy", ["local", "client"])
def test_automatic_policies_cannot_restore_a_disabled_tool(monkeypatch, tmp_path, policy):
    gate = ApprovalGate(policy=policy)
    if policy == "local":
        gate.set_mode("full")
    native, cfg, _ = native_fixture(monkeypatch, tmp_path, gate)
    cfg.disabled_tools = ['reach_get_clipboard', 'reach_launch_application']
    server = native.build_server(cfg, "test", gate)
    assert 'reach_get_clipboard' not in server.functions
    assert 'reach_launch_application' not in server.functions
    assert len(server.functions) == 13


def test_auto_grants_share_bounded_capacity_and_free_after_dispatch():
    async def run():
        gate = ApprovalGate(max_pending=2)
        gate.set_mode("low_risk")
        task = asyncio.create_task(gate.authorize('reach_get_clipboard', {}))
        request = await pending(gate)
        first = await gate.authorize('reach_wait', {"seconds": 0})
        with pytest.raises(ApprovalError, match="queue is full"):
            await gate.authorize('reach_screenshot', {})
        assert gate.decide(request["id"], True)
        clipboard = await task  # Converting one pending request does not need another slot.
        gate.consume(first, 'reach_wait', {"seconds": 0})
        next_grant = await gate.authorize('reach_screenshot', {})
        gate.consume(next_grant, 'reach_screenshot', {})
        gate.consume(clipboard, 'reach_get_clipboard', {})
    asyncio.run(run())


def test_auto_grant_expiry_frees_bounded_capacity():
    async def run():
        now = [10.0]
        gate = ApprovalGate(max_pending=1, clock=lambda: now[0])
        gate.set_mode("full", duration=900)
        unused = await gate.authorize('reach_wait', {})
        with pytest.raises(ApprovalError, match="queue is full"):
            await gate.authorize('reach_wait', {})
        now[0] += 60
        replacement = await gate.authorize('reach_wait', {})
        with pytest.raises(ApprovalError):
            gate.consume(unused, 'reach_wait', {})
        gate.consume(replacement, 'reach_wait', {})
    asyncio.run(run())


def test_screenshot_space_action_rejects_changed_mapping_after_approval(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from PIL import Image
    from reach_mcp.capture import CaptureHistory

    async def run():
        gate = ApprovalGate()
        gate.set_mode("low_risk")
        native, cfg, _ = native_fixture(monkeypatch, tmp_path, gate)
        history = CaptureHistory()
        monkeypatch.setattr(native, "CaptureHistory", lambda: history)
        monitor = SimpleNamespace(index=1, left=0, top=0, width=100, height=100)
        monkeypatch.setattr(native.screen, "primary", lambda: monitor)
        monkeypatch.setattr(native.screen, "monitors", lambda: [monitor])
        monkeypatch.setattr(native.screen, "grab", lambda *args: Image.new("RGB", (100, 100)))
        monkeypatch.setattr(native.winput, "cursor_pos", lambda: (20, 20))
        calls = []
        monkeypatch.setattr(native.winput, "move_to", lambda *args: calls.append(("move", args)))
        monkeypatch.setattr(native.winput, 'click', lambda *args: calls.append(('reach_click', args)))
        server = native.build_server(cfg, "test", gate)
        await server.functions['reach_screenshot']()
        first_id = history.last.id
        click = asyncio.create_task(server.functions['reach_click'](x=50, y=25))
        request = await pending(gate)
        assert request["arguments"]["_screenshot_id"] == first_id
        assert request["arguments"]["_screen_points"] == [[50, 25]]

        # A concurrent approved observation changes the image-to-screen mapping.
        monitor.left = 200
        await server.functions['reach_screenshot']()
        assert history.last.id != first_id
        assert history.last.to_screen(50, 25) == (250, 25)
        assert gate.decide(request["id"], True)
        with pytest.raises(ToolError, match="screenshot changed"):
            await click
        assert not calls
    asyncio.run(run())


def test_cancelled_dispatch_waiter_never_runs_later_or_keeps_grant(monkeypatch, tmp_path):
    async def run():
        gate = ApprovalGate(max_pending=1)
        gate.set_mode("full")
        native, _, server = native_fixture(monkeypatch, tmp_path, gate)
        started, release = threading.Event(), threading.Event()
        calls = []

        def blocking_read():
            started.set()
            assert release.wait(3)
            return "synthetic test data"

        monkeypatch.setattr(native.clipboard, "get_text", blocking_read)
        monkeypatch.setattr(native.winput, "cursor_pos", lambda: (20, 20))
        monkeypatch.setattr(native.winput, "move_to", lambda *args: calls.append(args))
        active = asyncio.create_task(server.functions['reach_get_clipboard']())
        try:
            for _ in range(200):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            assert started.is_set()
            queued = asyncio.create_task(server.functions['reach_move_mouse'](5, 5, coordinate_space="screen"))
            await asyncio.sleep(0.05)
            assert not queued.done()
            queued.cancel()
            with pytest.raises(asyncio.CancelledError):
                await queued
            # Queue capacity was one, so this also proves cancellation revoked
            # the unused automatic grant instead of keeping it until timeout.
            grant = await gate.authorize('reach_wait', {})
            gate.revoke(grant)
        finally:
            release.set()
            await active
        await asyncio.sleep(0.05)
        assert not calls
    asyncio.run(run())


@pytest.mark.parametrize("policy", ["", "ask", "full", None, False, [], {}])
def test_invalid_startup_policy_is_rejected(policy):
    with pytest.raises(ValueError, match="policy must be local or client"):
        ApprovalGate(policy=policy)


def test_client_policy_never_queues_or_requires_a_local_decision():
    async def run():
        gate = ApprovalGate(policy="client")
        assert gate.policy == "client"
        for tool, arguments in TOOL_CALLS:
            grant = await asyncio.wait_for(gate.authorize(tool, arguments, "chat"), 0.5)
            state = gate.snapshot()
            assert state["policy"] == state["mode"] == "client"
            assert state["pending"] == [] and state["expires_at"] is None
            assert not gate.decide("no-local-request", True)
            gate.consume(grant, tool, arguments, "chat")
            with pytest.raises(ApprovalError, match="already used"):
                gate.consume(grant, tool, arguments, "chat")
        gate.close()
        assert gate.snapshot()["closed"]
        assert gate.snapshot()["pending"] == []
        with pytest.raises(ApprovalError, match="closed"):
            await gate.authorize("reach_wait", {})
    asyncio.run(run())


@pytest.mark.parametrize("change", ["tool", "arguments", "client"])
def test_client_policy_grants_are_bound_and_cannot_be_replayed(change):
    async def run():
        gate = ApprovalGate(policy="client")
        args = {"seconds": 0, "screenshot": False}
        grant = await gate.authorize("reach_wait", args, "chat")
        tool, client = "reach_wait", "chat"
        altered = dict(args)
        if change == "tool":
            tool = "reach_screenshot"
        elif change == "arguments":
            altered["seconds"] = 1
        else:
            client = "other"
        with pytest.raises(ApprovalError):
            gate.consume(grant, tool, altered, client)
        with pytest.raises(ApprovalError):
            gate.consume(grant, "reach_wait", args, "chat")
    asyncio.run(run())


def test_client_policy_grants_expire_revoke_and_close_with_bounded_capacity():
    async def run():
        now = [10.0]
        gate = ApprovalGate(policy="client", max_pending=1, clock=lambda: now[0])
        first = await gate.authorize("reach_wait", {})
        with pytest.raises(ApprovalError, match="queue is full"):
            await gate.authorize("reach_wait", {})
        now[0] += 60
        second = await gate.authorize("reach_wait", {})
        with pytest.raises(ApprovalError):
            gate.consume(first, "reach_wait", {})
        gate.revoke(second)
        third = await gate.authorize("reach_wait", {})
        gate.close()
        with pytest.raises(ApprovalError):
            gate.consume(third, "reach_wait", {})
    asyncio.run(run())


@pytest.mark.parametrize("mode", ["ask", "low_risk", "full"])
def test_client_policy_cannot_be_changed_from_local_controls(mode):
    gate = ApprovalGate(policy="client")
    with pytest.raises(ApprovalError, match="server restart"):
        gate.set_mode(mode)
    state = gate.snapshot()
    assert state["policy"] == state["mode"] == "client"
    assert not state["closed"]


def test_client_policy_executes_authenticated_native_handler_without_local_queue(monkeypatch, tmp_path):
    async def run():
        gate = ApprovalGate(policy="client")
        native, cfg, server = native_fixture(monkeypatch, tmp_path, gate)
        monkeypatch.setattr(native.clipboard, "get_text", lambda: "synthetic result")
        result = await asyncio.wait_for(server.functions["reach_get_clipboard"](), 1)
        assert result == "synthetic result"
        assert gate.snapshot()["pending"] == []
        rows = [json.loads(row) for row in cfg.audit.path.read_text().splitlines()]
        assert len(rows) == 1 and rows[0]["ok"] is True
    asyncio.run(run())
