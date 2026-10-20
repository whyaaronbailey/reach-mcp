from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

from reach_mcp.processes import ProcessError, ProcessManager, _argv


def launch(manager, tmp_path, script, **kwargs):
    return manager.start(
        [sys.executable, "-X", "utf8", "-u", "-c", script], tmp_path,
        shell="program", **kwargs,
    )


def finished(manager, result, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = manager.read(result["job_id"], wait_seconds=.2)
        if not result["running"]:
            return result
    pytest.fail("The test job did not finish within its bound.")


def running_output(manager, result, needle, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = manager.read(result["job_id"], wait_seconds=.2)
        if needle in result["stdout"]:
            return result
        if not result["running"]:
            break
    pytest.fail("The expected test output was not produced.")


def assert_process_stopped(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if handle:
            try:
                assert kernel.WaitForSingleObject(handle, 3000) == 0
            finally:
                kernel.CloseHandle(handle)
    else:
        # A killed grandchild can briefly remain a zombie until its parent reaps it.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split()[2]
            except FileNotFoundError:
                return
            if state == "Z":
                return
            time.sleep(.05)
        pytest.fail("The child process survived cleanup.")


def test_output_exit_and_unicode(tmp_path):
    with ProcessManager() as manager:
        result = launch(
            manager, tmp_path,
            "import sys; print('snowman \\u2603'); print('failure',file=sys.stderr);sys.exit(7)",
        )
        result = finished(manager, result)
        assert result["status"] == "failed"
        assert result["exit_code"] == 7
        assert "snowman \u2603" in result["stdout"]
        assert "failure" in result["stderr"]
        assert result["output_complete"]
        assert "command" not in result
        assert manager.read(result["job_id"], cursor=result["next_cursor"])["stdout"] == ""


def test_cursors_and_output_bound(tmp_path):
    with ProcessManager(max_output_bytes=1024) as manager:
        result = finished(manager, launch(manager, tmp_path, "print('x'*10000,end='')"))
        assert result["output_bytes_seen"] == 10000
        assert result["output_bytes_retained"] <= 1024
        assert result["truncated"] and result["oldest_cursor"] > 0
        first = manager.read(result["job_id"], max_chars=13)
        second = manager.read(result["job_id"], cursor=first["next_cursor"], max_chars=19)
        assert first["stdout"] == "x" * 13
        assert second["stdout"] == "x" * 19
        assert second["next_cursor"] == first["next_cursor"] + 19
        assert first["has_more"] and not first["output_complete"]


def test_unicode_bound_is_bytes_and_keeps_valid_text(tmp_path):
    with ProcessManager(max_output_bytes=257) as manager:
        result = finished(manager, launch(manager, tmp_path, "print('\\u2603'*1000,end='')"))
        assert result["output_bytes_retained"] <= 257
        assert result["stdout"] and set(result["stdout"]) == {"\u2603"}
        assert "\ufffd" not in result["stdout"]


def test_input_is_queued_and_can_be_closed(tmp_path):
    with ProcessManager() as manager:
        result = launch(manager, tmp_path, "import sys; print(sys.stdin.read(),end='')")
        response = manager.write_stdin(result["job_id"], "hello \u2603\n")
        assert response["accepted_chars"] == 8
        manager.write_stdin(result["job_id"], "second\n", close=True)
        result = finished(manager, result)
        assert result["stdout"].replace("\r\n", "\n") == "hello \u2603\nsecond\n"
        assert result["stdin_closed"]
        with pytest.raises(ProcessError, match="no longer accepts"):
            manager.write_stdin(result["job_id"], "late")


def test_unread_stdin_does_not_block_caller(tmp_path):
    with ProcessManager(max_stdin_chars=65536) as manager:
        result = launch(manager, tmp_path, "import time;time.sleep(10)")
        start = time.monotonic()
        manager.write_stdin(result["job_id"], "a" * 65536)
        assert time.monotonic() - start < 1
        manager.cancel(result["job_id"])
        assert_process_stopped(result["pid"])


@pytest.mark.parametrize("action", ["cancel", "timeout", "safety", "close", "parent_exit"])
def test_process_tree_cleanup(tmp_path, action):
    stop = threading.Event()

    def safety():
        if stop.is_set():
            raise RuntimeError("private safety detail must not escape")

    manager = ProcessManager(safety_check=safety)
    try:
        script = (
            "import subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
            "print('CHILD='+str(p.pid),flush=True);"
            + ("time.sleep(.2)" if action == "parent_exit" else "time.sleep(30)")
        )
        result = launch(manager, tmp_path, script, timeout_seconds=.8 if action == "timeout" else 10)
        result = running_output(manager, result, "CHILD=")
        child = int(result["stdout"].split("CHILD=")[1].strip())
        if action == "cancel":
            manager.cancel(result["job_id"])
        elif action == "safety":
            stop.set()
        elif action == "close":
            manager.close()
        result = finished(manager, result)
        expected = {
            "cancel": "cancelled", "timeout": "timed_out", "safety": "safety_stopped",
            "close": "cancelled", "parent_exit": "completed",
        }
        assert result["status"] == expected[action]
        assert_process_stopped(result["pid"])
        assert_process_stopped(child)
        assert "private" not in str(result)
    finally:
        manager.close()


def test_safety_denies_start_and_stdin_without_leaking(tmp_path):
    blocked = threading.Event()

    def safety():
        if blocked.is_set():
            raise ValueError("secret value")

    with ProcessManager(safety_check=safety) as manager:
        blocked.set()
        with pytest.raises(ProcessError, match="safety controls") as error:
            launch(manager, tmp_path, "print('unreachable')")
        assert "secret" not in str(error.value)
        assert manager.list_jobs() == []


def test_limits_history_and_shutdown(tmp_path):
    manager = ProcessManager(max_jobs=1, max_history=1)
    result = launch(manager, tmp_path, "import time;time.sleep(10)")
    with pytest.raises(ProcessError, match="active job limit"):
        launch(manager, tmp_path, "pass")
    manager.cancel(result["job_id"])
    second = finished(manager, launch(manager, tmp_path, "print('second')"))
    with pytest.raises(ProcessError, match="not found"):
        manager.read(result["job_id"])
    assert [job["job_id"] for job in manager.list_jobs()] == [second["job_id"]]
    manager.close()
    with pytest.raises(ProcessError, match="shut down"):
        launch(manager, tmp_path, "pass")


def test_secret_environment_not_inherited(tmp_path, monkeypatch):
    monkeypatch.setenv("REACH_MCP_TOKEN", "not-a-real-secret")
    monkeypatch.setenv("COMPUTER_CONTROL_MCP_TOKEN", "not-a-real-secret")
    monkeypatch.setenv("GH_TOKEN", "not-a-real-secret")
    monkeypatch.setenv("OPENCODE_SERVER_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-secret")
    with ProcessManager() as manager:
        result = finished(manager, launch(
            manager, tmp_path,
            "import os;print([x in os.environ for x in "
            "['REACH_MCP_TOKEN','COMPUTER_CONTROL_MCP_TOKEN','GH_TOKEN','OPENCODE_SERVER_PASSWORD','OPENAI_API_KEY']])",
        ))
        assert result["stdout"].strip() == "[False, False, False, False, False]"


@pytest.mark.parametrize("kwargs", [
    {"cursor": -1}, {"cursor": True}, {"cursor": 9000},
    {"max_chars": 0}, {"max_chars": 1.1}, {"wait_seconds": 11}, {"wait_seconds": float("nan")},
])
def test_invalid_read_limits(tmp_path, kwargs):
    with ProcessManager() as manager:
        result = finished(manager, launch(manager, tmp_path, "print('short')"))
        with pytest.raises(ProcessError):
            manager.read(result["job_id"], **kwargs)


def test_invalid_commands_and_missing_program_are_safe(tmp_path):
    with ProcessManager(max_stdin_chars=2) as manager:
        for command in ([], ["bad\0argument"], "text instead of argv"):
            with pytest.raises(ProcessError):
                manager.start(command, tmp_path, shell="program")
        with pytest.raises(ProcessError) as error:
            manager.start(["private-unavailable-program-name"], tmp_path, shell="program")
        assert "private-unavailable" not in str(error.value)
        result = launch(manager, tmp_path, "import time;time.sleep(10)")
        with pytest.raises(ProcessError, match="character limit"):
            manager.write_stdin(result["job_id"], "long")
        for timeout in (-1, 0, float("inf"), True, 99999):
            with pytest.raises(ProcessError):
                launch(manager, tmp_path, "pass", timeout_seconds=timeout)


@pytest.mark.skipif(os.name != "nt", reason="Windows shell contract")
@pytest.mark.parametrize("shell,command,expected", [
    ("powershell", "[Console]::WriteLine('shell output \u2603')", "shell output \u2603"),
    ("cmd", "echo shell output", "shell output"),
])
def test_windows_shells(tmp_path, shell, command, expected):
    with ProcessManager() as manager:
        result = finished(manager, manager.start(command, tmp_path, shell=shell))
        assert expected in result["stdout"]
        assert result["exit_code"] == 0


def test_program_argv_is_not_interpreted_by_shell(tmp_path):
    with ProcessManager() as manager:
        marker = "value with spaces & | > $HOME"
        result = finished(manager, manager.start(
            [sys.executable, "-c", "import sys;print(sys.argv[1])", marker],
            tmp_path, shell="program",
        ))
        assert result["stdout"].strip() == marker


def test_shell_validation():
    with pytest.raises(ProcessError):
        _argv("hello", "unknown")
    with pytest.raises(ProcessError):
        _argv("", "powershell")
    with pytest.raises(ProcessError):
        _argv(["x" * 30000], "program")


def test_manager_configuration_limits():
    for kwargs in (
        {"max_jobs": 0}, {"max_jobs": 33}, {"max_jobs": 1.5}, {"max_output_bytes": 1},
        {"max_runtime_seconds": float("nan")}, {"max_history": 1},
    ):
        with pytest.raises(ProcessError):
            ProcessManager(**kwargs)

def test_python_output_is_utf8_without_manual_flags(tmp_path):
    with ProcessManager() as manager:
        result = finished(manager, manager.start(
            [sys.executable, "-c", "print(chr(0x2603))"], tmp_path, shell="program",
        ))
        assert result["stdout"].strip() == chr(0x2603)
        assert result["output_encoding"] == "utf-8"
