"""Native MCP integration of direct files and managed commands.

Uses a temporary local workspace and synthetic subprocesses only.
"""
import asyncio
import json
import sys
import threading

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from reach_mcp import server as native
from reach_mcp.approval import ApprovalGate
from reach_mcp.config import Config


def build(tmp_path, monkeypatch):
    cfg = Config()
    cfg.filesystem.workspace = tmp_path
    cfg.filesystem.allowed_roots = [tmp_path]
    cfg.audit.path = tmp_path / "audit.jsonl"
    cfg.safety.pause_file = tmp_path / "PAUSED"
    cfg.safety.action_delay_ms = 0
    cfg.safety.failsafe_corner = False
    monkeypatch.setattr(native.desktop, "status", lambda: {
        "available": True, "locked": False, "reason": None,
    })
    return cfg


async def call(server, tool, **arguments):
    result = await server.call_tool(tool, arguments)
    assert not result.is_error
    return json.loads(result.content[0].text)


def test_file_workflow_through_real_mcp_schema(monkeypatch, tmp_path):
    async def run():
        cfg = build(tmp_path, monkeypatch)
        server = native.build_server(cfg, "integration", ApprovalGate(policy="client"))
        async with server.settings.lifespan(server):
            capabilities = await call(server, "reach_get_capabilities")
            assert capabilities["filesystem"]["requires_hash_before_overwrite"]
            created = await call(server, "reach_write_file", path="code.py",
                                 content="print('before')\n", create=True)
            read = await call(server, "reach_read_file", path="code.py")
            assert read["content"] == "print('before')\n"
            assert created["sha256"] == read["sha256"]
            replaced = await call(server, "reach_replace_text", path="code.py",
                                  old="before", new="after", expected_sha256=read["sha256"])
            patch = "--- a/code.py\n+++ b/code.py\n@@ -1 +1 @@\n-print('after')\n+print('patched')\n"
            patched = await call(server, "reach_apply_patch", patch=patch,
                                 expected_sha256={"code.py": replaced["sha256"]})
            assert len(patched["files"]) == 1
            found = await call(server, "reach_search_files", query="patched", glob="*.py")
            assert found["matches"][0]["line"] == 1
            await call(server, "reach_make_directory", path="saved")
            moved = await call(server, "reach_move_file", source="code.py",
                               destination="saved/code.py",
                               expected_sha256=patched["files"][0]["sha256"])
            listed = await call(server, "reach_list_directory", path="saved")
            assert len(listed["entries"]) == 1
            await call(server, "reach_remove_file", path="saved/code.py",
                       expected_sha256=moved["sha256"])
            await call(server, "reach_remove_file", path="saved")
            assert not (tmp_path / "saved").exists()
    asyncio.run(run())


def test_locked_desktop_allows_file_reads_and_pause_blocks_mutations(monkeypatch, tmp_path):
    async def run():
        cfg = build(tmp_path, monkeypatch)
        (tmp_path / "file").write_bytes(b"keep")
        monkeypatch.setattr(native.desktop, "status", lambda: {
            "available": False, "locked": True, "reason": "locked",
        })
        def forbidden_desktop():
            raise AssertionError("A direct file read must not access the desktop")
        monkeypatch.setattr(native.desktop, "require_available", forbidden_desktop)
        server = native.build_server(cfg, "integration", ApprovalGate(policy="client"))
        async with server.settings.lifespan(server):
            read = await call(server, "reach_read_file", path="file")
            assert read["content"] == "keep"
            cfg.safety.pause_file.touch()
            with pytest.raises(ToolError, match="paused"):
                await call(server, "reach_write_file", path="new", content="blocked", create=True)
            with pytest.raises(ToolError, match="paused"):
                await call(server, "reach_run_command",
                           command=[sys.executable, "-c", "raise AssertionError('must not run')"],
                           shell="program")
            assert not (tmp_path / "new").exists()
            assert (await call(server, "reach_read_file", path="file"))["content"] == "keep"
    asyncio.run(run())


@pytest.mark.parametrize("files,commands,disabled", [
    (False, False, []), (True, False, ["reach_read_file"]), (False, True, []),
])
def test_disabled_capabilities_are_absent_from_discovery(monkeypatch, tmp_path, files, commands, disabled):
    async def run():
        cfg = build(tmp_path, monkeypatch)
        cfg.filesystem.enabled, cfg.execution.enabled = files, commands
        cfg.disabled_tools = disabled
        server = native.build_server(cfg, "integration", ApprovalGate(policy="client"))
        async with server.settings.lifespan(server):
            tools = {tool.name for tool in await server.list_tools()}
            assert ("reach_write_file" in tools) is files
            assert ("reach_run_command" in tools) is commands
            assert ("reach_read_file" in tools) is (files and "reach_read_file" not in disabled)
            assert "reach_get_capabilities" in tools
            for name in disabled:
                with pytest.raises(ToolError):
                    await call(server, name, path="anything")
    asyncio.run(run())


def test_terminal_output_stdin_exit_status_and_audit_privacy(monkeypatch, tmp_path):
    async def run():
        cfg = build(tmp_path, monkeypatch)
        cfg.audit.log_typed_text = True  # must not expose developer-tool payloads
        server = native.build_server(cfg, "integration", ApprovalGate(policy="client"))
        async with server.settings.lifespan(server):
            secret_content = "PRIVATE-CONTENT-TEST"
            secret_path = "PRIVATE-PATH-TEST.txt"
            await call(server, "reach_write_file", path=secret_path,
                       content=secret_content, create=True)
            command_secret = "PRIVATE-COMMAND-TEST"
            script = ("import sys; print('" + command_secret + "',flush=True);"
                      "print('PRIVATE-STDERR-TEST',file=sys.stderr,flush=True);"
                      "value=sys.stdin.readline();print(value.strip(),flush=True);sys.exit(7)")
            job = await call(server, "reach_run_command",
                             command=[sys.executable, "-u", "-c", script],
                             shell="program", wait_seconds=0)
            await call(server, "reach_write_process", job_id=job["job_id"],
                       text="PRIVATE-STDIN-TEST\n", close=True)
            output = {"stdout": "", "stderr": ""}
            cursor = 0
            for _ in range(20):
                status = await call(server, "reach_read_process", job_id=job["job_id"],
                                    cursor=cursor, wait_seconds=0.5)
                cursor = status["next_cursor"]
                for stream in output:
                    output[stream] += status[stream]
                if not status["running"] and not status["has_more"]:
                    break
            assert status["exit_code"] == 7
            assert command_secret in output["stdout"] and "PRIVATE-STDIN-TEST" in output["stdout"]
            assert "PRIVATE-STDERR-TEST" in output["stderr"]
            with pytest.raises(ToolError):
                await call(server, "reach_read_file", path="PRIVATE-FAILURE-PATH.txt")
            with pytest.raises(ToolError):
                await call(server, "reach_run_command",
                           command=["PRIVATE-FAILURE-COMMAND.exe"], shell="program")
        audit = cfg.audit.path.read_text(encoding="utf-8")
        for value in [secret_content, secret_path, command_secret, "PRIVATE-STDIN-TEST",
                      "PRIVATE-STDERR-TEST", "PRIVATE-FAILURE-PATH", "PRIVATE-FAILURE-COMMAND"]:
            assert value not in audit
        records = [json.loads(line) for line in audit.splitlines()]
        assert len({row["event_id"] for row in records}) == len(records)
        assert any(not row["ok"] for row in records)
    asyncio.run(run())


def test_terminal_poll_and_cancel_bypass_busy_desktop_queue(monkeypatch, tmp_path):
    async def run():
        cfg = build(tmp_path, monkeypatch)
        server = native.build_server(cfg, "integration", ApprovalGate(policy="client"))
        started, release = threading.Event(), threading.Event()
        def blocking_clipboard():
            started.set()
            assert release.wait(5)
            return "synthetic"
        monkeypatch.setattr(native.clipboard, "get_text", blocking_clipboard)
        async with server.settings.lifespan(server):
            active = asyncio.create_task(server.call_tool("reach_get_clipboard", {}))
            try:
                for _ in range(200):
                    if started.is_set():
                        break
                    await asyncio.sleep(0.005)
                assert started.is_set()
                job = await asyncio.wait_for(call(
                    server, "reach_run_command",
                    command=[sys.executable, "-u", "-c", "import time;print('ready',flush=True);time.sleep(30)"],
                    shell="program", wait_seconds=0), 2)
                poll = asyncio.create_task(call(server, "reach_read_process",
                                               job_id=job["job_id"], wait_seconds=2))
                await asyncio.sleep(0.05)
                cancelled = await asyncio.wait_for(
                    call(server, "reach_cancel_process", job_id=job["job_id"]), 2)
                await asyncio.wait_for(poll, 2)
                assert not cancelled["running"]
                jobs = await call(server, "reach_list_processes")
                assert any(item["job_id"] == job["job_id"] for item in jobs["jobs"])
                assert not active.done()  # desktop is still deliberately blocked
            finally:
                release.set()
                await active
    asyncio.run(run())
