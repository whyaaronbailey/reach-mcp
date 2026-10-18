import pytest

from reach_mcp.win import input as winput


@pytest.fixture(autouse=True)
def no_real_keyboard_state(monkeypatch):
    monkeypatch.setattr(winput.user32, "GetAsyncKeyState", lambda vk: 0)
    monkeypatch.setattr(winput.user32, "MapVirtualKeyW", lambda vk, mode: vk)


def test_unicode_input_releases_key_when_hold_is_interrupted(monkeypatch):
    events = []
    monkeypatch.setattr(winput, "_send", lambda batch: events.extend(
        (x.ki.wScan, x.ki.dwFlags) for x in batch))

    def interrupted(_seconds):
        raise RuntimeError("interrupted test hold")

    monkeypatch.setattr(winput.time, "sleep", interrupted)
    with pytest.raises(RuntimeError, match="interrupted"):
        winput.type_unicode("A")
    assert events == [
        (65, winput.KEYEVENTF_UNICODE),
        (65, winput.KEYEVENTF_UNICODE | winput.KEYEVENTF_KEYUP),
    ]


def test_every_utf16_unit_has_hold_and_release_gap(monkeypatch):
    events = []
    monkeypatch.setattr(winput, "_send", lambda batch: events.append(
        ("send", [(x.ki.wScan, x.ki.dwFlags) for x in batch])))
    monkeypatch.setattr(winput.time, "sleep", lambda seconds: events.append(("sleep", seconds)))
    winput.type_unicode("A\u65e5\U0001f680", interval=0)
    expected = []
    for unit in [65, 0x65e5, 0xd83d, 0xde80]:
        expected.extend([
            ("send", [(unit, winput.KEYEVENTF_UNICODE)]),
            ("sleep", 0.05),
            ("send", [(unit, winput.KEYEVENTF_UNICODE | winput.KEYEVENTF_KEYUP)]),
            ("sleep", 0.05),
        ])
    assert events == expected


def test_enter_and_tab_use_paced_real_keys(monkeypatch):
    events = []
    monkeypatch.setattr(winput, "_send", lambda batch: events.append(
        ("send", [(x.ki.wVk, x.ki.dwFlags) for x in batch])))
    monkeypatch.setattr(winput.time, "sleep", lambda seconds: events.append(("sleep", seconds)))
    winput.type_unicode("\r\n\t", interval=0.1)
    assert events == [
        ("send", [(0x0D, 0)]), ("sleep", 0.05),
        ("send", [(0x0D, winput.KEYEVENTF_KEYUP)]), ("sleep", 0.1),
        ("send", [(0x09, 0)]), ("sleep", 0.05),
        ("send", [(0x09, winput.KEYEVENTF_KEYUP)]), ("sleep", 0.1),
    ]


@pytest.mark.parametrize("modifier", [0x10, 0x11, 0x12, 0x5B, 0x5C])
def test_held_modifier_refuses_without_injecting_or_releasing(monkeypatch, modifier):
    events = []
    monkeypatch.setattr(winput.user32, "GetAsyncKeyState", lambda vk: 0x8000 if vk == modifier else 0)
    monkeypatch.setattr(winput, "_send", lambda batch: events.extend(batch))
    with pytest.raises(winput.InputBlockedError, match="modifier"):
        winput.type_unicode("ABC")
    assert events == []


@pytest.mark.parametrize("interval", [-1, float("nan"), float("inf"), True, "fast"])
def test_invalid_interval_does_not_inject(monkeypatch, interval):
    events = []
    monkeypatch.setattr(winput, "_send", lambda batch: events.extend(batch))
    with pytest.raises(ValueError, match="interval"):
        winput.type_unicode("ABC", interval=interval)
    assert events == []


def test_invalid_unicode_is_rejected_before_partial_input(monkeypatch):
    events = []
    monkeypatch.setattr(winput, "_send", lambda batch: events.extend(batch))
    with pytest.raises(UnicodeEncodeError):
        winput.type_unicode("safe-prefix\ud800")
    assert events == []



def test_typing_rechecks_kill_switch_between_characters(monkeypatch):
    events = []
    monkeypatch.setattr(winput, "_send", lambda batch: events.extend(batch))
    monkeypatch.setattr(winput.time, "sleep", lambda seconds: None)
    checks = []
    def check():
        checks.append(True)
        if len(checks) == 2:
            raise RuntimeError("paused")
    with pytest.raises(RuntimeError, match="paused"):
        winput.type_unicode("ab", check_allowed=check)
    assert len(events) == 2
    assert len(checks) == 2
