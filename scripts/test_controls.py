"""Local test harness helpers; these do not add a production approval bypass."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request


def select_test_mode(state_dir: Path, mode: str, duration: int = 300) -> None:
    """Use an isolated test child's real owner API, without printing its capability."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        files = list(state_dir.glob("control-panel-*.url"))
        if len(files) == 1:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("Test control panel did not become ready")
    url = urllib.parse.urlsplit(files[0].read_text(encoding="utf-8").strip())
    if url.scheme != "http" or url.hostname != "127.0.0.1" or not url.fragment or url.username or url.query:
        raise RuntimeError("Invalid isolated test panel address")
    origin = f"http://127.0.0.1:{url.port}"
    request = urllib.request.Request(
        origin + "/api/mode",
        data=json.dumps({"mode": mode, "duration": duration}).encode(),
        headers={
            "Authorization": f"Bearer {url.fragment}",
            "Origin": origin,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        state = json.load(response)
    if state.get("mode") != mode:
        raise RuntimeError("Test approval mode was not applied")


class ChildJob:
    """Kill attached test children and their descendants when the job closes."""

    def __init__(self):
        self.handle = None
        if os.name != "nt":
            return
        from ctypes import wintypes as w

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                ("flags", w.DWORD), ("minimum_working_set", ctypes.c_size_t),
                ("maximum_working_set", ctypes.c_size_t), ("active_processes", w.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes"
            )]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits), ("io", IoCounters),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t),
            ]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.kernel.SetInformationJobObject.restype = w.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = w.BOOL
        self.kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        self.kernel.TerminateJobObject.restype = w.BOOL
        self.kernel.QueryInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
        self.kernel.QueryInformationJobObject.restype = w.BOOL
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)

    def attach(self, process) -> None:
        if self.handle and not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                accounting = ctypes.create_string_buffer(48)
                if not self.kernel.QueryInformationJobObject(self.handle, 1, accounting, 48, None):
                    break
                if int.from_bytes(accounting.raw[40:44], "little") == 0:
                    break
                time.sleep(0.05)
            self.kernel.CloseHandle(self.handle)
            self.handle = None
