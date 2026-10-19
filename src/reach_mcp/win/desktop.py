"""Read interactive-session availability without unlocking or switching desktops."""
from __future__ import annotations

import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
user32.OpenInputDesktop.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
user32.OpenInputDesktop.restype = wintypes.HANDLE
user32.CloseDesktop.argtypes = (wintypes.HANDLE,)
wtsapi32.WTSQuerySessionInformationW.argtypes = (
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
)
wtsapi32.WTSFreeMemory.argtypes = (ctypes.c_void_p,)

UNAVAILABLE_MESSAGE = (
    "Reach MCP cannot access the interactive Windows desktop. "
    "The VM may be locked, disconnected, or showing a secure Windows prompt. "
    "Restore an unlocked Windows session before retrying; local approval controls "
    "do not resolve this. An interrupted action may be partially applied: "
    "inspect the target before retrying text or clicks."
)


class DesktopUnavailableError(RuntimeError):
    """The interactive desktop is unavailable; never attempt to unlock it."""


class _SessionInfo(ctypes.Structure):
    _fields_ = [
        ("session_id", wintypes.DWORD),
        ("connection_state", ctypes.c_int),
        ("session_flags", wintypes.LONG),
        ("station_name", wintypes.WCHAR * 33),
        ("user_name", wintypes.WCHAR * 21),
        ("domain_name", wintypes.WCHAR * 18),
        *[(name, ctypes.c_longlong) for name in (
            "logon_time", "connect_time", "disconnect_time", "last_input_time", "current_time",
        )],
        *[(name, wintypes.DWORD) for name in (
            "incoming_bytes", "outgoing_bytes", "incoming_frames", "outgoing_frames",
            "incoming_compressed_bytes", "outgoing_compressed_bytes",
        )],
    ]


class _SessionInfoEx(ctypes.Structure):
    _fields_ = [("level", wintypes.DWORD), ("data", _SessionInfo)]


def _session_flags() -> tuple[int, int] | None:
    pointer = ctypes.c_void_p()
    size = wintypes.DWORD()
    # WTS_CURRENT_SESSION / WTSSessionInfoEx. Windows 10+ uses 0=locked, 1=unlocked.
    if not wtsapi32.WTSQuerySessionInformationW(
        None, 0xFFFFFFFF, 25, ctypes.byref(pointer), ctypes.byref(size)
    ):
        return None
    try:
        if not pointer or size.value < ctypes.sizeof(_SessionInfoEx):
            return None
        info = ctypes.cast(pointer, ctypes.POINTER(_SessionInfoEx)).contents
        if info.level != 1 or info.data.session_flags not in (0, 1):
            return None
        return info.data.connection_state, info.data.session_flags
    finally:
        wtsapi32.WTSFreeMemory(pointer)


def status() -> dict:
    session = _session_flags()
    if session is None:
        return {"available": False, "locked": None, "reason": "session_unknown"}
    connection, flags = session
    if flags == 0:
        return {"available": False, "locked": True, "reason": "locked"}
    if connection != 0:  # WTSActive
        return {"available": False, "locked": False, "reason": "disconnected"}
    handle = user32.OpenInputDesktop(0, False, 0x0001)  # DESKTOP_READOBJECTS only.
    if not handle:
        return {"available": False, "locked": False, "reason": "secure_or_unavailable"}
    user32.CloseDesktop(handle)
    return {"available": True, "locked": False, "reason": None}


def require_available() -> None:
    if not status()["available"]:
        raise DesktopUnavailableError(UNAVAILABLE_MESSAGE)
