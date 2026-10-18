"""Screenshot scaling and the screenshot-space -> screen-space coordinate mapping.

Models see a downscaled image, so the coordinates they pick are in *image*
pixels. Every capture records how to map those back to physical screen pixels;
action tools default to interpreting coordinates in the space of the most
recent screenshot.
"""

from __future__ import annotations

import io
import threading
from dataclasses import asdict, dataclass

from PIL import Image, ImageDraw


@dataclass(frozen=True)
class Capture:
    id: int
    left: int  # screen-space origin of the captured region
    top: int
    width: int  # captured region size in screen pixels
    height: int
    image_width: int  # size of the image returned to the model
    image_height: int
    scale: float  # image px per screen px (<= 1)
    source: str  # e.g. "monitor 1", "window 0x1234 (Notepad)", "region"

    def to_screen(self, x: float, y: float) -> tuple[int, int]:
        if not (0 <= x <= self.image_width and 0 <= y <= self.image_height):
            raise ValueError(
                f"({x}, {y}) is outside screenshot #{self.id} "
                f"({self.image_width}x{self.image_height}); take a new screenshot"
            )
        sx = self.left + min(round(x / self.scale), self.width - 1)
        sy = self.top + min(round(y / self.scale), self.height - 1)
        return sx, sy

    def to_image(self, sx: int, sy: int) -> tuple[int, int] | None:
        ix, iy = (sx - self.left) * self.scale, (sy - self.top) * self.scale
        if 0 <= ix < self.image_width and 0 <= iy < self.image_height:
            return round(ix), round(iy)
        return None

    def describe(self) -> dict:
        return asdict(self)


def fit_scale(width: int, height: int, max_long_edge: int) -> float:
    long_edge = max(width, height)
    return 1.0 if long_edge <= max_long_edge else max_long_edge / long_edge


def scale_image(img: Image.Image, scale: float) -> Image.Image:
    if scale >= 1.0:
        return img
    size = (max(1, round(img.width * scale)), max(1, round(img.height * scale)))
    return img.resize(size, Image.Resampling.LANCZOS)


def draw_cursor(img: Image.Image, at: tuple[int, int]) -> None:
    """Draw a small high-contrast crosshair; real cursors are not captured by GDI."""
    x, y = at
    d = ImageDraw.Draw(img)
    for color, w in (("black", 3), ("white", 1)):
        d.line([(x - 8, y), (x + 8, y)], fill=color, width=w)
        d.line([(x, y - 8), (x, y + 8)], fill=color, width=w)


def encode(img: Image.Image, fmt: str, quality: int) -> bytes:
    buf = io.BytesIO()
    if fmt == "jpeg":
        img.save(buf, format="JPEG", quality=quality, optimize=True)
    else:
        img.save(buf, format="PNG", optimize=False, compress_level=6)
    return buf.getvalue()


class CaptureHistory:
    def __init__(self):
        self._lock = threading.Lock()
        self._next = 1
        self.last: Capture | None = None

    def new(self, **kw) -> Capture:
        with self._lock:
            cap = Capture(id=self._next, **kw)
            self._next += 1
            self.last = cap
            return cap
