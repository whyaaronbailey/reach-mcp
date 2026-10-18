import ctypes
import json
import sys
import pytest

CASES = [
    ("plain title", "plain title"),
    ("caf\u00e9 \u2014 \u65e5\u672c\u8a9e", "caf\u00e9 \u2014 \u65e5\u672c\u8a9e"),
    ("launch \U0001f680", "launch \U0001f680"),
    ("launch \ud83d\ude80", "launch \U0001f680"),
    ("before \ud83d after", "before \ufffd after"),
    ("before \ude80 after", "before \ufffd after"),
    ("\ud83d\ud83d\ude80", "\ufffd\U0001f680"),
]

def assert_transport_safe(actual, expected):
    from mcp.types import JSONRPCResponse
    assert actual == expected
    response = JSONRPCResponse(jsonrpc="2.0", id=1, result={"content":[{"type":"text","text":actual}]})
    wire = response.model_dump_json(by_alias=True).encode("utf-8")
    assert json.loads(wire)["result"]["content"][0]["text"] == expected

@pytest.mark.skipif(sys.platform != "win32", reason="Win32 UTF-16 boundary")
@pytest.mark.parametrize("reader_name", ["_text", "_class"])
@pytest.mark.parametrize(("source", "expected"), CASES)
def test_window_text_transport(monkeypatch, reader_name, source, expected):
    from reach_mcp.win import windows
    assert ctypes.sizeof(ctypes.c_wchar) == 2
    raw = source.encode("utf-16-le", errors="surrogatepass")
    units = len(raw)//2
    def write_text(hwnd, buffer, capacity):
        assert capacity >= units + 1
        ctypes.memmove(buffer, raw+b"\0\0", len(raw)+2)
        return units
    monkeypatch.setattr(windows.user32, "GetWindowTextLengthW", lambda hwnd: units)
    monkeypatch.setattr(windows.user32, "GetWindowTextW", write_text)
    monkeypatch.setattr(windows.user32, "GetClassNameW", write_text)
    assert_transport_safe(getattr(windows, reader_name)(1234), expected)

@pytest.mark.skipif(sys.platform != "win32", reason="Win32 UTF-16 boundary")
@pytest.mark.parametrize(("source", "expected"), CASES)
def test_clipboard_text_transport(monkeypatch, source, expected):
    from reach_mcp.win import clipboard
    raw = source.encode("utf-16-le", errors="surrogatepass")+b"\0\0"
    storage = ctypes.create_string_buffer(raw)
    monkeypatch.setattr(clipboard.user32, "OpenClipboard", lambda hwnd: True)
    monkeypatch.setattr(clipboard.user32, "CloseClipboard", lambda: True)
    monkeypatch.setattr(clipboard.user32, "IsClipboardFormatAvailable", lambda fmt: True)
    monkeypatch.setattr(clipboard.user32, "GetClipboardData", lambda fmt: 1)
    monkeypatch.setattr(clipboard.kernel32, "GlobalLock", lambda h: ctypes.addressof(storage))
    monkeypatch.setattr(clipboard.kernel32, "GlobalUnlock", lambda h: True)
    assert_transport_safe(clipboard.get_text(), expected)
