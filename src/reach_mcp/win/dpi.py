"""Process DPI awareness.

Must run before any window, screen or cursor API is touched, so that every
coordinate in the process (screenshots, SetCursorPos, window rects) is in
physical pixels and they all agree with one another.
"""

from __future__ import annotations

import ctypes

_DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = ctypes.c_void_p(-4)
_mode: str | None = None


def make_process_dpi_aware() -> str:
    global _mode
    if _mode is not None:
        return _mode
    user32 = ctypes.windll.user32
    try:
        if user32.SetProcessDpiAwarenessContext(_DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2):
            _mode = "per-monitor-v2"
            return _mode
    except AttributeError:
        pass
    try:
        if ctypes.windll.shcore.SetProcessDpiAwareness(2) == 0:
            _mode = "per-monitor"
            return _mode
    except (AttributeError, OSError):
        pass
    _mode = "system" if user32.SetProcessDPIAware() else "unaware"
    return _mode


def dpi_mode() -> str:
    return _mode or "not-set"
