"""Monitor layout and screen capture (via mss / GDI)."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass

import mss
from PIL import Image

_local = threading.local()


def _sct() -> mss.base.MSSBase:
    # mss handles are not thread-safe; keep one per thread.
    sct = getattr(_local, "sct", None)
    if sct is None:
        sct = mss.mss()
        _local.sct = sct
    return sct


@dataclass(frozen=True)
class Monitor:
    index: int  # 1-based, stable for the session; matches mss numbering
    left: int
    top: int
    width: int
    height: int
    primary: bool

    def to_dict(self) -> dict:
        return asdict(self)

    def contains(self, x: int, y: int) -> bool:
        return self.left <= x < self.left + self.width and self.top <= y < self.top + self.height


def monitors() -> list[Monitor]:
    out = []
    for i, m in enumerate(_sct().monitors[1:], start=1):
        out.append(Monitor(i, m["left"], m["top"], m["width"], m["height"], m["left"] == 0 and m["top"] == 0))
    return out


def virtual_screen() -> tuple[int, int, int, int]:
    m = _sct().monitors[0]
    return m["left"], m["top"], m["width"], m["height"]


def primary() -> Monitor:
    mons = monitors()
    return next((m for m in mons if m.primary), mons[0])


def monitor_at(x: int, y: int) -> Monitor | None:
    return next((m for m in monitors() if m.contains(x, y)), None)


def grab(left: int, top: int, width: int, height: int) -> Image.Image:
    shot = _sct().grab({"left": left, "top": top, "width": width, "height": height})
    return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
