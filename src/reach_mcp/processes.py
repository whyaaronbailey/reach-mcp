"""Bounded terminal jobs owned by the Reach server.

Commands run as the current Windows user; this is an execution interface, not a
sandbox. Callers validate working directories and authorize each operation.
Output and command text are never written to logs by this module.
Capture decodes UTF-8 with replacement; PowerShell and Python are configured
accordingly. Legacy cmd/native utilities may require their own UTF-8 setting.
"""
from __future__ import annotations

import base64
import codecs
import math
import os
import queue
import signal
import subprocess
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


class ProcessError(RuntimeError):
    """A safe, user-facing process error without command or output payloads."""


def _number(value, minimum: float, maximum: float, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProcessError(f"{label} must be a number.")
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ProcessError(f"{label} is outside the configured limits.")
    return float(value)


def _integer(value, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProcessError(f"{label} must be an integer.")
    return int(_number(value, minimum, maximum, label))


def _argv(command: str | list[str], shell: str) -> list[str]:
    if shell == "program":
        if not isinstance(command, list) or not command or any(
            not isinstance(arg, str) or "\0" in arg for arg in command
        ) or not command[0]:
            raise ProcessError("Program commands require a nonempty argument list.")
        result = command
    elif shell in {"powershell", "cmd"}:
        if not isinstance(command, str) or not command.strip() or "\0" in command:
            raise ProcessError("Shell commands require nonempty text without nulls.")
        if os.name != "nt":
            raise ProcessError("PowerShell and cmd execution require Windows.")
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer)):
            raise ProcessError("The Windows system directory is unavailable.")
        system = Path(buffer.value)
        if shell == "powershell":
            prefix = (
                "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);"
                "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
                "$OutputEncoding=[Text.UTF8Encoding]::new($false);"
            )
            encoded = base64.b64encode((prefix + command).encode("utf-16-le")).decode("ascii")
            result = [str(system / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
                      "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
        else:
            result = [str(system / "cmd.exe"), "/d", "/s", "/c", command]
    else:
        raise ProcessError("Shell must be powershell, cmd, or program.")
    if sum(len(arg) + 3 for arg in result) > 30000:
        raise ProcessError("The command exceeds the Windows command-line limit.")
    return result


def _child_environment() -> dict[str, str]:
    # Server credentials must not accidentally appear in command environment dumps.
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("REACH_MCP_", "COMPUTER_CONTROL_MCP_"))
        and not any(part in key.upper() for part in (
            "PASSWORD", "SECRET", "TOKEN", "CREDENTIAL", "API_KEY", "APIKEY",
            "ACCESS_KEY", "PRIVATE_KEY", "SIGNING_KEY",
        ))
    }
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    return environment


class _PosixProcess:
    """Portable test/development implementation with a separate process group."""
    def __init__(self, argv, cwd, environment):
        self.process = subprocess.Popen(
            argv, cwd=cwd, env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            bufsize=0,
        )
        self.pid = self.process.pid
        self.stdin, self.stdout, self.stderr = (
            self.process.stdin, self.process.stdout, self.process.stderr
        )

    def poll(self):
        return self.process.poll()

    def stop_tree(self):
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def close(self):
        self.stop_tree()
        self.process.wait(timeout=5)


class _WindowsProcess:
    """Start suspended, attach a kill-on-close Job Object, then resume.

    CPython's Windows process primitive returns both initial handles, allowing
    job ownership before user code or child processes can execute.
    """
    def __init__(self, argv, cwd, environment):
        import ctypes
        import msvcrt
        import _winapi
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        for name, args, result in (
            ("CreateJobObjectW", [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            ("SetInformationJobObject", [wintypes.HANDLE, ctypes.c_int,
                                         ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            ("AssignProcessToJobObject", [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            ("TerminateJobObject", [wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            ("ResumeThread", [wintypes.HANDLE], wintypes.DWORD),
        ):
            function = getattr(kernel, name)
            function.argtypes, function.restype = args, result
        self.kernel, self.api = kernel, _winapi
        self.handle = self.job = None
        self.stdin = self.stdout = self.stderr = None
        fds = []
        thread_handle = None
        try:
            self.job = kernel.CreateJobObjectW(None, None)
            if not self.job:
                raise OSError("CreateJobObject failed")
            limits = ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
            if not kernel.SetInformationJobObject(
                self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            ):
                raise OSError("SetInformationJobObject failed")
            input_read, input_write = os.pipe()
            fds.extend((input_read, input_write))
            output_read, output_write = os.pipe()
            fds.extend((output_read, output_write))
            error_read, error_write = os.pipe()
            fds.extend((error_read, error_write))
            child_fds = (input_read, output_write, error_write)
            handles = [msvcrt.get_osfhandle(fd) for fd in child_fds]
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESTDHANDLES
            startup.hStdInput, startup.hStdOutput, startup.hStdError = handles
            startup.lpAttributeList = {"handle_list": handles}
            self.handle, thread_handle, self.pid, _ = _winapi.CreateProcess(
                None, subprocess.list2cmdline(argv), None, None, True,
                0x00000004 | 0x08000000, environment, str(cwd), startup,
            )
            if not kernel.AssignProcessToJobObject(self.job, self.handle):
                raise OSError("AssignProcessToJobObject failed")
            if kernel.ResumeThread(thread_handle) == 0xFFFFFFFF:
                raise OSError("ResumeThread failed")
            for fd in child_fds:
                os.close(fd)
                fds.remove(fd)
            for name, fd, mode in (
                ("stdin", input_write, "wb"),
                ("stdout", output_read, "rb"),
                ("stderr", error_read, "rb"),
            ):
                setattr(self, name, os.fdopen(fd, mode, buffering=0))
                fds.remove(fd)
        except BaseException:
            if self.handle is not None:
                _winapi.TerminateProcess(self.handle, 1)
            if self.job:
                _winapi.CloseHandle(self.job)
                self.job = None
            if self.handle is not None:
                _winapi.CloseHandle(self.handle)
                self.handle = None
            for pipe in (self.stdin, self.stdout, self.stderr):
                if pipe is not None:
                    pipe.close()
            raise
        finally:
            if thread_handle is not None:
                _winapi.CloseHandle(thread_handle)
            for fd in fds:
                os.close(fd)

    def poll(self):
        if self.api.WaitForSingleObject(self.handle, 0) == 0:
            return self.api.GetExitCodeProcess(self.handle)
        return None

    def stop_tree(self):
        if self.job:
            self.kernel.TerminateJobObject(self.job, 1)

    def close(self):
        if self.job:
            self.api.CloseHandle(self.job)
            self.job = None
        if self.handle is not None:
            self.api.WaitForSingleObject(self.handle, 5000)
            self.api.CloseHandle(self.handle)
            self.handle = None


@dataclass
class _Job:
    id: str
    process: object
    cwd: str
    shell: str
    timeout: float
    started: float = field(default_factory=time.monotonic)
    status: str = "running"
    exit_code: int | None = None
    reason: str | None = None
    events: deque = field(default_factory=deque)
    cursor: int = 0
    retained_bytes: int = 0
    bytes_seen: int = 0
    stdin_pending: int = 0
    stdin_closed: bool = False
    stdin_error: bool = False
    finished: float | None = None
    cancel: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    condition: threading.Condition = field(default_factory=threading.Condition)
    input_queue: queue.Queue = field(default_factory=queue.Queue)
    threads: list = field(default_factory=list)


class ProcessManager:
    def __init__(
        self, *, max_jobs: int = 4, max_history: int = 32,
        max_output_bytes: int = 1_048_576, max_runtime_seconds: float = 3600,
        max_stdin_chars: int = 65536, safety_check: Callable[[], None] | None = None,
    ):
        self.max_jobs = _integer(max_jobs, 1, 32, "Job count")
        self.max_history = _integer(max_history, self.max_jobs, 1024, "History size")
        self.max_output_bytes = _integer(max_output_bytes, 256, 16_777_216, "Output size")
        self.max_runtime_seconds = _number(max_runtime_seconds, .1, 86400, "Runtime")
        self.max_stdin_chars = _integer(max_stdin_chars, 1, 1_048_576, "Input size")
        self.safety_check = safety_check
        self._jobs: OrderedDict[str, _Job] = OrderedDict()
        self._lock = threading.RLock()
        self._closed = False

    def _safe(self):
        if self.safety_check is not None:
            try:
                self.safety_check()
            except Exception:
                raise ProcessError("Execution is stopped by the safety controls.") from None

    def start(
        self, command: str | list[str], cwd: str | Path, *, shell: str = "powershell",
        timeout_seconds: float = 300, wait_seconds: float = 0,
    ) -> dict:
        timeout = _number(timeout_seconds, .1, self.max_runtime_seconds, "Timeout")
        _number(wait_seconds, 0, 10, "Wait")
        argv = _argv(command, shell)
        try:
            directory = Path(cwd).resolve(strict=True)
        except (OSError, ValueError):
            raise ProcessError("The working directory is unavailable.") from None
        if not directory.is_dir() or str(directory).startswith(("\\\\", "//")):
            raise ProcessError("A local working directory is required.")
        self._safe()
        with self._lock:
            if self._closed:
                raise ProcessError("The process manager is shut down.")
            if sum(not item.done.is_set() for item in self._jobs.values()) >= self.max_jobs:
                raise ProcessError("The active job limit has been reached; cancel a job first.")
            while len(self._jobs) >= self.max_history:
                oldest = next((key for key, item in self._jobs.items() if item.done.is_set()), None)
                if oldest is None:
                    break
                del self._jobs[oldest]
            try:
                process_type = _WindowsProcess if os.name == "nt" else _PosixProcess
                process = process_type(argv, directory, _child_environment())
            except Exception:
                raise ProcessError("The command could not be started. Check the program and working directory.") from None
            job = _Job(uuid.uuid4().hex, process, str(directory), shell, timeout)
            self._jobs[job.id] = job
            for stream in ("stdout", "stderr"):
                thread = threading.Thread(
                    target=self._reader, args=(job, stream), daemon=True,
                    name=f"reach-output-{job.id[:8]}-{stream}",
                )
                job.threads.append(thread)
                thread.start()
            writer = threading.Thread(target=self._writer, args=(job,), daemon=True,
                                      name=f"reach-input-{job.id[:8]}")
            job.threads.append(writer)
            writer.start()
            threading.Thread(target=self._watch, args=(job,), daemon=True,
                             name=f"reach-job-{job.id[:8]}").start()
        return self.read(job.id, wait_seconds=wait_seconds)

    def _get(self, job_id: str) -> _Job:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise ProcessError("The job was not found or its retained history has expired.")
        return job

    def _append(self, job, stream, text, raw_bytes):
        with job.condition:
            job.bytes_seen += raw_bytes
            if text:
                start = job.cursor
                job.cursor += len(text)
                data = text.encode("utf-8")
                if len(data) > self.max_output_bytes:
                    tail = data[-self.max_output_bytes:].decode("utf-8", errors="ignore")
                    start += len(text) - len(tail)
                    text, data = tail, tail.encode("utf-8")
                job.events.append((start, stream, text, len(data)))
                job.retained_bytes += len(data)
                while job.retained_bytes > self.max_output_bytes and job.events:
                    job.retained_bytes -= job.events.popleft()[3]
            job.condition.notify_all()

    def _reader(self, job, stream):
        pipe = getattr(job.process, stream)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while raw := pipe.read(8192):
                self._append(job, stream, decoder.decode(raw), len(raw))
            self._append(job, stream, decoder.decode(b"", final=True), 0)
        except (OSError, ValueError):
            pass
        finally:
            pipe.close()

    def _writer(self, job):
        try:
            while True:
                data = job.input_queue.get()
                if data is None:
                    break
                try:
                    view = memoryview(data)
                    while view:
                        count = job.process.stdin.write(view)
                        if not count:
                            raise BrokenPipeError
                        view = view[count:]
                finally:
                    with job.condition:
                        job.stdin_pending -= len(data)
        except (OSError, ValueError):
            with job.condition:
                job.stdin_error = True
        finally:
            with job.condition:
                job.stdin_closed = True
            try:
                job.process.stdin.close()
            except (OSError, ValueError):
                pass

    def _watch(self, job):
        try:
            while True:
                code = job.process.poll()
                if code is not None:
                    job.exit_code = code
                    break
                if job.cancel.is_set():
                    job.reason = "cancelled"
                elif time.monotonic() - job.started >= job.timeout:
                    job.reason = "timeout"
                else:
                    try:
                        self._safe()
                    except ProcessError:
                        job.reason = "safety_stop"
                if job.reason is not None:
                    job.process.stop_tree()
                if job.cancel.wait(.1) and job.reason is None:
                    job.reason = "cancelled"
            # Kill surviving descendants even when their parent exits successfully.
            job.process.stop_tree()
            job.input_queue.put(None)
            for thread in job.threads:
                thread.join(timeout=2)
        finally:
            job.process.close()
            with job.condition:
                job.finished = time.monotonic()
                job.status = {
                    "cancelled": "cancelled", "timeout": "timed_out",
                    "safety_stop": "safety_stopped",
                }.get(job.reason, "completed" if job.exit_code == 0 else "failed")
                job.done.set()
                job.condition.notify_all()

    def read(
        self, job_id: str, *, cursor: int = 0, max_chars: int = 20000,
        wait_seconds: float = 0,
    ) -> dict:
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise ProcessError("The output cursor must be a nonnegative integer.")
        maximum = _integer(max_chars, 1, 100000, "Output characters")
        wait = _number(wait_seconds, 0, 10, "Wait")
        job = self._get(job_id)
        with job.condition:
            if cursor > job.cursor:
                raise ProcessError("The output cursor is beyond this job's output.")
            if wait:
                job.condition.wait_for(lambda: job.cursor > cursor or job.done.is_set(), wait)
            oldest = job.events[0][0] if job.events else job.cursor
            position = max(cursor, oldest)
            output = {"stdout": [], "stderr": []}
            remaining = maximum
            for start, stream, text, _ in job.events:
                end = start + len(text)
                if position >= end:
                    continue
                offset = max(position - start, 0)
                piece = text[offset:offset + remaining]
                output[stream].append(piece)
                position = start + offset + len(piece)
                remaining -= len(piece)
                if not remaining:
                    break
            return {
                "job_id": job.id, "pid": job.process.pid, "cwd": job.cwd,
                "shell": job.shell, "status": job.status,
                "running": not job.done.is_set(), "exit_code": job.exit_code,
                "reason": job.reason, "stdout": "".join(output["stdout"]),
                "stderr": "".join(output["stderr"]), "output_encoding": "utf-8",
                "decode_errors": "replace", "next_cursor": position,
                "oldest_cursor": oldest, "truncated": cursor < oldest,
                "has_more": position < job.cursor,
                "output_complete": job.done.is_set() and position >= job.cursor,
                "output_bytes_seen": job.bytes_seen,
                "output_bytes_retained": job.retained_bytes,
                "stdin_closed": job.stdin_closed, "stdin_error": job.stdin_error,
                "duration_seconds": round((job.finished or time.monotonic()) - job.started, 3),
            }

    def write_stdin(self, job_id: str, text: str = "", *, close: bool = False) -> dict:
        if not isinstance(text, str) or len(text) > self.max_stdin_chars:
            raise ProcessError("Standard input exceeds the configured character limit.")
        if not isinstance(close, bool):
            raise ProcessError("Close must be true or false.")
        self._safe()
        job = self._get(job_id)
        data = text.encode("utf-8")
        with job.condition:
            if job.done.is_set() or job.stdin_closed:
                raise ProcessError("This job no longer accepts standard input.")
            if job.stdin_pending + len(data) > self.max_stdin_chars * 4:
                raise ProcessError("The pending standard-input buffer is full.")
            if data:
                job.stdin_pending += len(data)
                job.input_queue.put(data)
            if close:
                job.stdin_closed = True
                job.input_queue.put(None)
            return {"job_id": job.id, "accepted_chars": len(text),
                    "stdin_close_requested": close, "running": True}

    def cancel(self, job_id: str) -> dict:
        job = self._get(job_id)
        job.cancel.set()
        job.done.wait(3)
        return self.read(job.id)

    def list_jobs(self) -> list[dict]:
        with self._lock:
            return [
                {key: value for key, value in self.read(job_id, max_chars=1).items()
                 if key in {"job_id", "pid", "cwd", "shell", "status", "running",
                            "exit_code", "reason", "duration_seconds"}}
                for job_id in self._jobs
            ]

    def close(self):
        with self._lock:
            self._closed = True
            jobs = list(self._jobs.values())
        for job in jobs:
            job.cancel.set()
        deadline = time.monotonic() + 5
        for job in jobs:
            job.done.wait(max(0, deadline - time.monotonic()))

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()
