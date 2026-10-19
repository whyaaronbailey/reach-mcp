"""Mouse and keyboard injection via SendInput.

Coordinates are physical virtual-desktop pixels (the process is made DPI-aware
at startup). Windows' UIPI rule applies: a non-elevated process cannot inject
input into an elevated (administrator) window; SendInput then reports fewer
events sent and we raise ``InputBlockedError``.
"""

from __future__ import annotations

import ctypes
import math
import time
from ctypes import wintypes

from .keys import Key
from .desktop import DesktopUnavailableError

user32 = ctypes.WinDLL("user32", use_last_error=True)

ULONG_PTR = ctypes.c_size_t

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_HWHEEL = 0x1000
WHEEL_DELTA = 120

MAPVK_VK_TO_VSC = 0


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
user32.SendInput.restype = wintypes.UINT
user32.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
user32.SetCursorPos.restype = wintypes.BOOL
user32.GetCursorPos.argtypes = (ctypes.POINTER(wintypes.POINT),)
user32.GetCursorPos.restype = wintypes.BOOL
user32.MapVirtualKeyW.argtypes = (wintypes.UINT, wintypes.UINT)
user32.MapVirtualKeyW.restype = wintypes.UINT
user32.GetAsyncKeyState.argtypes = (ctypes.c_int,)
user32.GetAsyncKeyState.restype = ctypes.c_short


class InputBlockedError(RuntimeError):
    pass


def _send(inputs: list[INPUT]) -> None:
    if not inputs:
        return
    arr = (INPUT * len(inputs))(*inputs)
    sent = user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))
    if sent != len(inputs):
        err = ctypes.get_last_error()
        raise InputBlockedError(
            f"SendInput delivered {sent}/{len(inputs)} events (error {err}). The target is probably "
            "an elevated/administrator window or the secure desktop (UAC, lock screen); a "
            "non-elevated server cannot control it."
        )


def _mouse(flags: int, data: int = 0) -> INPUT:
    inp = INPUT(type=INPUT_MOUSE)
    inp.mi = MOUSEINPUT(0, 0, ctypes.c_uint32(data).value, flags, 0, 0)
    return inp


def _key(key: Key, up: bool) -> INPUT:
    flags = KEYEVENTF_KEYUP if up else 0
    if key.extended:
        flags |= KEYEVENTF_EXTENDEDKEY
    scan = user32.MapVirtualKeyW(key.vk, MAPVK_VK_TO_VSC)
    inp = INPUT(type=INPUT_KEYBOARD)
    inp.ki = KEYBDINPUT(key.vk, scan, flags, 0, 0)
    return inp


def _unicode(code_unit: int, up: bool) -> INPUT:
    inp = INPUT(type=INPUT_KEYBOARD)
    inp.ki = KEYBDINPUT(0, code_unit, KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if up else 0), 0, 0)
    return inp


# ---------------------------------------------------------------- mouse

_BUTTONS = {
    "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
    "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
    "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
}


def cursor_pos() -> tuple[int, int]:
    pt = wintypes.POINT()
    if not user32.GetCursorPos(ctypes.byref(pt)):
        error = ctypes.WinError(ctypes.get_last_error())
        if error.winerror == 5:
            raise DesktopUnavailableError() from error
        raise error
    return pt.x, pt.y


def move_to(x: int, y: int) -> None:
    if not user32.SetCursorPos(int(x), int(y)):
        error = ctypes.WinError(ctypes.get_last_error())
        if error.winerror == 5:
            raise DesktopUnavailableError() from error
        raise error


def button_down(button: str = "left") -> None:
    _send([_mouse(_BUTTONS[button][0])])


def button_up(button: str = "left") -> None:
    _send([_mouse(_BUTTONS[button][1])])


def click(button: str = "left", count: int = 1, interval: float = 0.05) -> None:
    down, up = _BUTTONS[button]
    for i in range(count):
        _send([_mouse(down), _mouse(up)])
        if i + 1 < count:
            time.sleep(interval)


def drag(path: list[tuple[int, int]], button: str = "left", duration: float = 0.4) -> None:
    if len(path) < 2:
        raise ValueError("drag needs at least a start and an end point")
    move_to(*path[0])
    time.sleep(0.05)
    button_down(button)
    try:
        # Interpolate so apps that track intermediate moves (sliders, canvases) see motion.
        steps_per_segment = max(4, int(duration * 60 / (len(path) - 1)))
        delay = duration / ((len(path) - 1) * steps_per_segment)
        for (x0, y0), (x1, y1) in zip(path, path[1:]):
            for s in range(1, steps_per_segment + 1):
                t = s / steps_per_segment
                move_to(round(x0 + (x1 - x0) * t), round(y0 + (y1 - y0) * t))
                time.sleep(delay)
    finally:
        button_up(button)


def scroll(direction: str, amount: int) -> None:
    """Scroll by ``amount`` wheel notches. ``direction`` is up/down/left/right."""
    if direction in ("up", "down"):
        delta = WHEEL_DELTA * amount * (1 if direction == "up" else -1)
        flag = MOUSEEVENTF_WHEEL
    elif direction in ("left", "right"):
        delta = WHEEL_DELTA * amount * (1 if direction == "right" else -1)
        flag = MOUSEEVENTF_HWHEEL
    else:
        raise ValueError("direction must be up, down, left or right")
    _send([_mouse(flag, delta)])


# ---------------------------------------------------------------- keyboard


def key_down(key: Key) -> None:
    _send([_key(key, up=False)])


def key_up(key: Key) -> None:
    _send([_key(key, up=True)])


def press_combo(keys: list[Key], hold: float = 0.0) -> None:
    """Press keys in order, hold, then release in reverse order (always releases)."""
    pressed: list[Key] = []
    try:
        for k in keys:
            key_down(k)
            pressed.append(k)
            time.sleep(0.01)
        if hold:
            time.sleep(hold)
    finally:
        for k in reversed(pressed):
            key_up(k)


_ENTER = Key(0x0D)
_TAB = Key(0x09)


# Unicode packets share VK_PACKET in the target message queue. Modern Windows
# text controls in a busy VM can mistranslate packets sent faster than their
# input processing. Pace every UTF-16 unit, including both surrogate halves.
# SendInput reports queue insertion, not application consumption; callers still
# need to verify the resulting text.
_UNICODE_HOLD_SECONDS = 0.05
_UNICODE_RELEASE_SECONDS = 0.05
_MODIFIER_VKS = (0x10, 0x11, 0x12, 0x5B, 0x5C)  # Shift, Ctrl, Alt, Win


def _ensure_no_modifiers() -> None:
    # Do not release a key the owner may be physically holding. Fail before
    # injecting text instead of turning it into shortcuts or altered characters.
    if any(user32.GetAsyncKeyState(vk) & 0x8000 for vk in _MODIFIER_VKS):
        raise InputBlockedError(
            "A modifier key is held. Release Shift, Ctrl, Alt and Windows keys "
            "before typing text."
        )


def _paced_key(down: INPUT, up: INPUT, release_delay: float) -> None:
    _send([down])
    try:
        time.sleep(_UNICODE_HOLD_SECONDS)
    finally:
        _send([up])
    time.sleep(release_delay)


def type_unicode(text: str, interval: float = _UNICODE_RELEASE_SECONDS, *, check_allowed=None) -> None:
    """Type Unicode using paced UTF-16 packets, without modifying the clipboard.

    Enter and Tab use real key presses. Each code unit has a minimum 50 ms
    keydown hold and 50 ms release gap; an explicit interval can increase the
    release gap but cannot remove this compatibility pacing. Verify text in the
    target: successful SendInput alone is not an acknowledgment by the app.
    """
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval) or interval < 0:
        raise ValueError("Typing interval must be a finite non-negative number.")
    delay = max(interval, _UNICODE_RELEASE_SECONDS)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Validate the complete string before injecting any part of it.
    text.encode("utf-16-le")
    for ch in text:
        if check_allowed is not None:
            check_allowed()
        _ensure_no_modifiers()
        if ch in ("\n", "\t"):
            key = _ENTER if ch == "\n" else _TAB
            _paced_key(_key(key, False), _key(key, True), delay)
        else:
            units = ch.encode("utf-16-le")
            for i in range(0, len(units), 2):
                code = int.from_bytes(units[i : i + 2], "little")
                _paced_key(_unicode(code, False), _unicode(code, True), delay)
