"""Top-level window enumeration and activation."""

from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from dataclasses import asdict, dataclass

from . import input as winput
from .keys import Key

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
dwmapi = ctypes.WinDLL("dwmapi")

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes = (WNDENUMPROC, wintypes.LPARAM)
user32.IsWindowVisible.argtypes = (wintypes.HWND,)
user32.IsWindow.argtypes = (wintypes.HWND,)
user32.IsIconic.argtypes = (wintypes.HWND,)
user32.IsZoomed.argtypes = (wintypes.HWND,)
user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
user32.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
user32.GetForegroundWindow.restype = wintypes.HWND
user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
user32.BringWindowToTop.argtypes = (wintypes.HWND,)
user32.GetWindow.argtypes = (wintypes.HWND, wintypes.UINT)
user32.GetWindow.restype = wintypes.HWND
user32.GetWindowLongW.argtypes = (wintypes.HWND, ctypes.c_int)
user32.GetWindowLongW.restype = ctypes.c_long
dwmapi.DwmGetWindowAttribute.argtypes = (wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD)
kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = (
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

DWMWA_EXTENDED_FRAME_BOUNDS = 9
DWMWA_CLOAKED = 14
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SW_RESTORE = 9
GW_OWNER = 4
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080


@dataclass
class WindowInfo:
    hwnd: int
    title: str
    process: str
    pid: int
    class_name: str
    left: int
    top: int
    width: int
    height: int
    minimized: bool
    maximized: bool
    foreground: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _text(hwnd: int) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def _class(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def _pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def _process_name(pid: int) -> str:
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
        return ""
    finally:
        kernel32.CloseHandle(h)


def _cloaked(hwnd: int) -> bool:
    val = wintypes.DWORD()
    hr = dwmapi.DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, ctypes.byref(val), ctypes.sizeof(val))
    return hr == 0 and val.value != 0


def window_rect(hwnd: int) -> tuple[int, int, int, int]:
    """Visible bounds (left, top, width, height), excluding the invisible resize border."""
    r = wintypes.RECT()
    hr = dwmapi.DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(r), ctypes.sizeof(r))
    if hr != 0 and not user32.GetWindowRect(hwnd, ctypes.byref(r)):
        raise ctypes.WinError(ctypes.get_last_error())
    return r.left, r.top, r.right - r.left, r.bottom - r.top


def info(hwnd: int) -> WindowInfo:
    left, top, width, height = window_rect(hwnd)
    pid = _pid(hwnd)
    return WindowInfo(
        hwnd=int(hwnd),
        title=_text(hwnd),
        process=_process_name(pid),
        pid=pid,
        class_name=_class(hwnd),
        left=left,
        top=top,
        width=width,
        height=height,
        minimized=bool(user32.IsIconic(hwnd)),
        maximized=bool(user32.IsZoomed(hwnd)),
        foreground=int(user32.GetForegroundWindow() or 0) == int(hwnd),
    )


def list_windows() -> list[WindowInfo]:
    """Visible, titled, uncloaked top-level app windows in Z-order (topmost first)."""
    hwnds: list[int] = []

    @WNDENUMPROC
    def _cb(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd) or user32.GetWindowTextLengthW(hwnd) == 0:
            return True
        if user32.GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW:
            return True
        if _cloaked(hwnd):
            return True
        hwnds.append(int(hwnd))
        return True

    user32.EnumWindows(_cb, 0)
    out = []
    for h in hwnds:
        try:
            out.append(info(h))
        except OSError:
            continue  # window vanished mid-enumeration
    return out


def foreground() -> WindowInfo | None:
    h = user32.GetForegroundWindow()
    return info(h) if h else None


def exists(hwnd: int) -> bool:
    return bool(user32.IsWindow(hwnd))


def activate(hwnd: int, timeout: float = 1.5) -> bool:
    """Restore and bring a window to the foreground. Returns True when it is foreground."""
    if not exists(hwnd):
        raise ValueError(f"no window with hwnd {hwnd}")
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, SW_RESTORE)
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.05)
    deadline = time.monotonic() + timeout
    while True:
        if int(user32.GetForegroundWindow() or 0) == int(hwnd):
            return True
        # Windows only lets the process that received the last input steal focus;
        # a synthetic Alt tap makes us that process (standard workaround).
        winput.press_combo([Key(0x12)])
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.1)
        if time.monotonic() > deadline:
            return int(user32.GetForegroundWindow() or 0) == int(hwnd)
