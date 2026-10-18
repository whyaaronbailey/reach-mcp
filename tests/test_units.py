from pathlib import Path

import pytest

from reach_mcp import config
from reach_mcp.audit import AuditLog
from reach_mcp.capture import Capture, fit_scale
from reach_mcp.win.keys import parse_combo, parse_key


def test_named_and_alias_keys():
    assert parse_key("Return").vk == 0x0D
    assert parse_key("Page_Down") == parse_key("pgdn")
    assert parse_key("super").vk == 0x5B
    assert parse_key("F12").vk == 0x7B
    assert parse_key("a").vk == ord("A")
    with pytest.raises(ValueError):
        parse_key("definitely-not-a-key")


def test_combo_order_and_plus():
    keys = parse_combo("ctrl+shift+t")
    assert [k.vk for k in keys] == [0x11, 0x10, ord("T")]
    assert parse_combo("ctrl+plus")[-1].vk == 0xBB
    assert parse_combo("ctrl++")[0].vk == 0x11
    with pytest.raises(ValueError):
        parse_combo("ctrl+")


def test_capture_mapping_roundtrip():
    cap = Capture(id=1, left=-1920, top=0, width=1920, height=1080, image_width=1568, image_height=882,
                  scale=1568 / 1920, source="monitor 2")
    sx, sy = cap.to_screen(784, 441)
    assert (sx, sy) == (-960, 540)
    assert cap.to_image(sx, sy) == (784, 441)
    assert cap.to_screen(1568, 882) == (-1, 1079)  # clamped to the last pixel
    with pytest.raises(ValueError):
        cap.to_screen(2000, 10)


def test_fit_scale():
    assert fit_scale(1280, 720, 1568) == 1.0
    assert fit_scale(3840, 2160, 1568) == pytest.approx(1568 / 3840)


def test_config_defaults_and_validation(tmp_path: Path):
    p = tmp_path / "c.toml"
    p.write_text('[screenshot]\nmax_long_edge = 1024\n[tools]\ndisabled = ["reach_launch_application"]\n')
    cfg = config.load(p)
    assert cfg.screenshot.max_long_edge == 1024
    assert cfg.disabled_tools == ['reach_launch_application']
    p.write_text("[safety]\nnot_a_key = 1\n")
    with pytest.raises(ValueError):
        config.load(p)


def test_audit_hides_text(tmp_path: Path):
    log = AuditLog(tmp_path / "a.jsonl", enabled=True, log_text=False)
    log.record('reach_type_text', {"text": "hunter2"}, True, 0.0)
    line = (tmp_path / "a.jsonl").read_text()
    assert "hunter2" not in line and '"chars": 7' in line



def test_audit_hides_launch_arguments(tmp_path: Path):
    log = AuditLog(tmp_path / "launch.jsonl")
    log.record('reach_launch_application', {"target": "private-document.txt", "arguments": "--key confidential"}, True, 0.0)
    line = (tmp_path / "launch.jsonl").read_text()
    assert "confidential" not in line
    assert "private-document" not in line
