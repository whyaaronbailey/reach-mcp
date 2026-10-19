"""Regression tests use synthetic sessions and never inject desktop input."""
import asyncio
import ctypes
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from reach_mcp import server as native
from reach_mcp.approval import ApprovalGate
from reach_mcp.config import Config
from reach_mcp.win import desktop, input as winput


@pytest.mark.parametrize("session,can_open,reason", [
    ((0, 1), True, None),
    ((0, 0), True, "locked"),
    ((4, 1), True, "disconnected"),
    ((0, 1), False, "secure_or_unavailable"),
    (None, True, "session_unknown"),
])
def test_session_status_and_handle_cleanup(monkeypatch, session, can_open, reason):
    opened, closed = [], []
    monkeypatch.setattr(desktop, "_session_flags", lambda: session)
    monkeypatch.setattr(desktop.user32, "OpenInputDesktop",
                        lambda *a: opened.append(a) or (17 if can_open else None))
    monkeypatch.setattr(desktop.user32, "CloseDesktop", lambda h: closed.append(h))
    result = desktop.status()
    assert result["reason"] == reason
    assert result["available"] is (reason is None)
    assert closed == ([17] if reason is None else [])
    assert bool(opened) is (session == (0, 1))


@pytest.mark.parametrize("flags", [0, 1])
def test_windows_session_structure_and_buffer_release(monkeypatch, flags):
    info = desktop._SessionInfoEx()
    info.level = 1
    info.data.connection_state = 0
    info.data.session_flags = flags
    freed = []
    def query(_server, session, info_class, pointer, size):
        assert session == 0xFFFFFFFF and info_class == 25
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(info)
        ctypes.cast(size, ctypes.POINTER(desktop.wintypes.DWORD))[0] = ctypes.sizeof(info)
        return True
    monkeypatch.setattr(desktop.wtsapi32, "WTSQuerySessionInformationW", query)
    monkeypatch.setattr(desktop.wtsapi32, "WTSFreeMemory", lambda p: freed.append(p.value))
    assert desktop._session_flags() == (0, flags)
    assert freed == [ctypes.addressof(info)]


def make_server(tmp_path):
    cfg = Config()
    cfg.audit.path = tmp_path / "audit.jsonl"
    cfg.safety.pause_file = tmp_path / "PAUSED"
    return native.build_server(cfg, "desktop-regression", ApprovalGate(policy="client")), cfg


@pytest.mark.parametrize("tool,args", [
    ("reach_type_text", {"text": "synthetic private typed text"}),
    ("reach_launch_application", {"target": "notepad.exe"}),
])
def test_locked_client_policy_blocks_before_any_input(monkeypatch, tmp_path, tool, args):
    monkeypatch.setattr(desktop, "status", lambda: {
        "available": False, "locked": True, "reason": "locked",
    })
    def forbidden(*a, **kw):
        raise AssertionError("Locked desktop must not be accessed")
    monkeypatch.setattr(winput, "cursor_pos", forbidden)
    monkeypatch.setattr(winput, "type_unicode", forbidden)
    monkeypatch.setattr(native.os, "startfile", forbidden)
    server, cfg = make_server(tmp_path)
    with pytest.raises(ToolError, match="interactive Windows desktop"):
        asyncio.run(server.call_tool(tool, args))
    audit = cfg.audit.path.read_text()
    assert "synthetic private typed text" not in audit
    assert json.loads(audit)["ok"] is False


def test_screen_info_reports_lock_without_cursor_access(monkeypatch, tmp_path):
    monkeypatch.setattr(desktop, "status", lambda: {
        "available": False, "locked": True, "reason": "locked",
    })
    monkeypatch.setattr(native.windows, "foreground", lambda: None)
    monkeypatch.setattr(native.screen, "monitors", lambda: [])
    monkeypatch.setattr(native.screen, "virtual_screen", lambda: (0, 0, 100, 100))
    def forbidden():
        raise AssertionError("Cursor must not be queried on a locked desktop")
    monkeypatch.setattr(winput, "cursor_pos", forbidden)
    server, _ = make_server(tmp_path)
    result = asyncio.run(server.call_tool("reach_get_screen_info", {}))
    info = json.loads(result.content[0].text)
    assert info["approval_policy"] == "client"
    assert info["desktop"]["locked"] is True and info["cursor"] is None


def test_cursor_access_denied_has_typed_desktop_error(monkeypatch):
    monkeypatch.setattr(winput.user32, "GetCursorPos", lambda p: 0)
    ctypes.set_last_error(5)
    with pytest.raises(desktop.DesktopUnavailableError):
        winput.cursor_pos()


@pytest.mark.parametrize("policy", ["client", "local"])
def test_server_instructions_match_startup_policy(tmp_path, policy):
    cfg = Config()
    cfg.audit.path = tmp_path / "audit.jsonl"
    server = native.build_server(cfg, approval_gate=ApprovalGate(policy=policy))
    assert f"Approval policy: {policy}." in server.instructions
    if policy == "client":
        assert "server starts in Ask" not in server.instructions
        assert "no VM-local approval" in server.instructions
