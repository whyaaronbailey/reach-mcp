"""Key-name parsing for hotkeys such as ``ctrl+shift+t``.

Accepts common spellings from several agent ecosystems (xdotool names like
``Return``/``Page_Down``/``super``, macOS-ish ``cmd``/``option``, and plain
Windows names) so prompts written for other computer-use tools still work.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass


@dataclass(frozen=True)
class Key:
    vk: int
    extended: bool = False
    implies_shift: bool = False  # e.g. "?" on a US layout is Shift+/


_NAMED: dict[str, Key] = {
    # modifiers
    "ctrl": Key(0x11), "control": Key(0x11), "lctrl": Key(0xA2), "rctrl": Key(0xA3, True),
    "controll": Key(0xA2), "controlr": Key(0xA3, True),
    "shift": Key(0x10), "lshift": Key(0xA0), "rshift": Key(0xA1),
    "shiftl": Key(0xA0), "shiftr": Key(0xA1),
    "alt": Key(0x12), "option": Key(0x12), "lalt": Key(0xA4), "ralt": Key(0xA5, True),
    "altl": Key(0xA4), "altr": Key(0xA5, True), "altgr": Key(0xA5, True),
    "win": Key(0x5B, True), "lwin": Key(0x5B, True), "rwin": Key(0x5C, True),
    "super": Key(0x5B, True), "superl": Key(0x5B, True), "superr": Key(0x5C, True),
    "meta": Key(0x5B, True), "cmd": Key(0x5B, True), "command": Key(0x5B, True),
    "windows": Key(0x5B, True),
    # editing / navigation
    "enter": Key(0x0D), "return": Key(0x0D), "kpenter": Key(0x0D, True),
    "esc": Key(0x1B), "escape": Key(0x1B),
    "tab": Key(0x09), "space": Key(0x20), "spacebar": Key(0x20),
    "backspace": Key(0x08), "bksp": Key(0x08),
    "delete": Key(0x2E, True), "del": Key(0x2E, True),
    "insert": Key(0x2D, True), "ins": Key(0x2D, True),
    "home": Key(0x24, True), "end": Key(0x23, True),
    "pageup": Key(0x21, True), "pgup": Key(0x21, True), "prior": Key(0x21, True),
    "pagedown": Key(0x22, True), "pgdn": Key(0x22, True), "next": Key(0x22, True),
    "up": Key(0x26, True), "down": Key(0x28, True), "left": Key(0x25, True), "right": Key(0x27, True),
    "apps": Key(0x5D, True), "menu": Key(0x5D, True), "contextmenu": Key(0x5D, True),
    "capslock": Key(0x14), "numlock": Key(0x90, True), "scrolllock": Key(0x91),
    "printscreen": Key(0x2C, True), "print": Key(0x2C, True), "prtsc": Key(0x2C, True),
    "pause": Key(0x13), "break": Key(0x13),
    # numpad
    "multiply": Key(0x6A), "add": Key(0x6B), "separator": Key(0x6C),
    "subtract": Key(0x6D), "decimal": Key(0x6E), "divide": Key(0x6F, True),
    # media / browser
    "volumemute": Key(0xAD), "volumedown": Key(0xAE), "volumeup": Key(0xAF),
    "medianext": Key(0xB0), "mediaprev": Key(0xB1), "mediastop": Key(0xB2), "mediaplaypause": Key(0xB3),
    "browserback": Key(0xA6), "browserforward": Key(0xA7), "browserrefresh": Key(0xA8),
    # punctuation spelled out (the literal characters also work)
    "plus": Key(0xBB), "equal": Key(0xBB), "equals": Key(0xBB),
    "minus": Key(0xBD), "comma": Key(0xBC), "period": Key(0xBE), "dot": Key(0xBE),
    "slash": Key(0xBF), "backslash": Key(0xDC), "semicolon": Key(0xBA),
    "apostrophe": Key(0xDE), "quote": Key(0xDE), "grave": Key(0xC0), "backtick": Key(0xC0),
    "bracketleft": Key(0xDB), "bracketright": Key(0xDD),
}
for _i in range(1, 25):
    _NAMED[f"f{_i}"] = Key(0x6F + _i)
for _i in range(10):
    _NAMED[f"numpad{_i}"] = Key(0x60 + _i)
    _NAMED[f"kp{_i}"] = Key(0x60 + _i)

MODIFIER_VKS = {0x10, 0x11, 0x12, 0x5B, 0x5C, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}


def _normalize(name: str) -> str:
    n = name.strip().lower()
    if len(n) > 1:
        n = n.replace("_", "").replace("-", "").replace(" ", "")
    return n


def _vk_for_char(ch: str) -> Key:
    if "a" <= ch.lower() <= "z" or "0" <= ch <= "9":
        return Key(ord(ch.upper()))
    # Layout-aware lookup for punctuation; low byte is the VK, -1 means unmapped.
    res = ctypes.windll.user32.VkKeyScanW(ord(ch))
    if res == -1 or (res & 0xFF) == 0xFF:
        raise ValueError(f"no key on the current keyboard layout produces {ch!r}; use type_text instead")
    if res & 0x600:  # needs Ctrl or Alt (AltGr) - not expressible as a single key
        raise ValueError(f"{ch!r} needs AltGr on this layout; use type_text instead")
    return Key(res & 0xFF, implies_shift=bool(res & 0x100))


def parse_key(name: str) -> Key:
    if name == "":
        raise ValueError("empty key name")
    if len(name) == 1:
        return _vk_for_char(name)
    key = _NAMED.get(_normalize(name))
    if key is None:
        raise ValueError(f"unknown key name {name!r}")
    return key


def parse_combo(combo: str) -> list[Key]:
    """Parse ``ctrl+shift+t``. A literal plus is written ``ctrl+plus`` or ``ctrl++``."""
    combo = combo.strip()
    if not combo:
        raise ValueError("empty key combination")
    parts: list[str] = []
    if combo.endswith("++"):
        parts = [p for p in combo[:-2].split("+") if p] + ["+"]
    elif combo == "+":
        parts = ["+"]
    else:
        parts = combo.split("+")
    if any(p.strip() == "" for p in parts):
        raise ValueError(f"malformed key combination {combo!r}")
    keys = [parse_key(p.strip()) for p in parts]
    if any(k.implies_shift for k in keys) and not any(k.vk in (0x10, 0xA0, 0xA1) for k in keys):
        keys.insert(len(keys) - 1, Key(0x10))
    return keys
