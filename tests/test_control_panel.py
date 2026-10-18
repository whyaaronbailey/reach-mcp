"""Exercise the owner HTTP boundary without accessing a desktop."""
import asyncio
from pathlib import Path
import socket
import urllib.error
import urllib.request

from starlette.testclient import TestClient
import pytest

from reach_mcp.approval import ApprovalGate
from reach_mcp.control_panel import ControlPanel


@pytest.fixture
def panel(tmp_path):
    value = ControlPanel(ApprovalGate(), tmp_path / "private")
    value.origin = "http://127.0.0.1:8766"
    yield value
    value.gate.close()


def owner_headers(panel):
    return {"Authorization": f"Bearer {panel.token}", "Origin": panel.origin}


def test_panel_does_not_embed_capability(panel):
    with TestClient(panel.create_app(), base_url=panel.origin) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert panel.token not in response.text
        assert "Ask for approval" in response.text
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert client.get("/health").json()["status"] == "ok"
        assert client.get("/api/state").status_code == 401


@pytest.mark.parametrize("headers", [
    {}, {"Authorization": "Bearer invalid"},
    {"Origin": "https://attacker.invalid"},
    {"Host": "attacker.invalid"}, {"Host": "localhost:8766"},
])
def test_panel_rejects_unauthorized_call(panel, headers):
    with TestClient(panel.create_app(), base_url=panel.origin) as client:
        assert client.post("/api/mode", json={"mode": "full", "duration": 60},
                           headers=headers).status_code in {401, 403}
        assert panel.gate.snapshot()["mode"] == "ask"


def test_mutations_require_origin_and_json(panel):
    with TestClient(panel.create_app(), base_url=panel.origin) as client:
        auth = {"Authorization": f"Bearer {panel.token}"}
        assert client.post("/api/mode", json={"mode": "full", "duration": 60},
                           headers=auth).status_code == 403
        headers = owner_headers(panel)
        assert client.post("/api/mode", content="{}", headers=headers).status_code == 415
        assert client.post("/api/mode", json={"mode": "full", "duration": 60},
                           headers={**headers, "Origin": "https://attacker.invalid"}).status_code == 403
        assert client.options("/api/mode", headers={"Origin": "https://attacker.invalid"}).status_code == 403


def test_valid_modes_and_revoke(panel):
    with TestClient(panel.create_app(), base_url=panel.origin) as client:
        headers = owner_headers(panel)
        for mode in ("low_risk", "full", "ask"):
            r = client.post("/api/mode", json={"mode": mode, "duration": 60}, headers=headers)
            assert r.status_code == 200
            assert r.json()["mode"] == mode
        assert client.get("/api/state?token=anything", headers=headers).status_code == 403


@pytest.mark.parametrize("payload", [
    [], {"mode": "invalid", "duration": 60}, {"mode": [], "duration": 60},
    {"mode": "full", "duration": 0}, {"mode": "full", "duration": True},
    {"mode": "full", "duration": 3601}, {"mode": "full", "duration": 60, "extra": True},
])
def test_invalid_commands_fail_closed(panel, payload):
    with TestClient(panel.create_app(), base_url=panel.origin) as client:
        assert client.post("/api/mode", json=payload, headers=owner_headers(panel)).status_code == 400
        assert panel.gate.snapshot()["mode"] == "ask"


def test_bounded_body_and_expired_decision(panel):
    with TestClient(panel.create_app(), base_url=panel.origin) as client:
        headers = {**owner_headers(panel), "Content-Type": "application/json"}
        assert client.post("/api/mode", content=b" " * 5000, headers=headers).status_code == 413
        assert client.post("/api/decision", json={"id": "expired", "allow": True},
                           headers=headers).status_code == 409
        assert client.post("/api/decision", json={"id": "expired", "allow": "yes"},
                           headers=headers).status_code == 400


def test_local_listener_lifecycle_and_token_file(tmp_path):
    panel = ControlPanel(ApprovalGate(), tmp_path / "private")
    try:
        panel.start()
        assert panel.origin.startswith("http://127.0.0.1:")
        assert panel.url_file.read_text().strip() == f"{panel.origin}/#{panel.token}"
        with urllib.request.urlopen(panel.origin + "/health", timeout=3) as response:
            assert response.status == 200
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(panel.origin + "/api/state", timeout=3)
        assert denied.value.code == 401
    finally:
        panel.stop()
    assert not panel.url_file.exists()
    assert panel.gate.snapshot()["closed"]
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", panel.port)) != 0


def test_acl_helper_ignores_parent_powershell_module_path(monkeypatch, tmp_path):
    import os
    import subprocess
    from reach_mcp.control_panel import secure_state_directory
    if os.name != "nt":
        pytest.skip("Windows PowerShell ACL boundary")
    inherited = str(tmp_path / "incompatible-powershell7-modules")
    monkeypatch.setenv("PSModulePath", inherited)
    real_run = subprocess.run
    checked = []

    def run_isolated(*args, **kwargs):
        assert not any(key.upper() == "PSMODULEPATH" for key in kwargs["env"])
        checked.append(True)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run_isolated)
    secure_state_directory(tmp_path / "private")
    secure_state_directory(tmp_path / "private")  # Already-secure ACL is idempotent.
    assert checked == [True, True]
    assert os.environ["PSModulePath"] == inherited


@pytest.mark.parametrize("failure", ["acl", "timeout", "launch"])
def test_acl_failure_stays_closed_and_redacts_subprocess_details(monkeypatch, tmp_path, failure):
    import os
    import subprocess
    from reach_mcp.control_panel import secure_state_directory
    if os.name != "nt":
        pytest.skip("Windows PowerShell ACL boundary")

    def fail(*args, **kwargs):
        if failure == "acl":
            raise subprocess.CalledProcessError(
                1, args[0],
                stderr=b"REACH_ACL_ERROR apply System.UnauthorizedAccessException Denied\nsynthetic-private-data",
            )
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], 15, stderr=b"synthetic-private-data")
        raise OSError("synthetic-private-data")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="Unable to restrict") as error:
        secure_state_directory(tmp_path / "private")
    assert "synthetic-private-data" not in str(error.value)
    assert str(tmp_path) not in str(error.value)
    if failure == "acl":
        assert "stage=apply" in str(error.value) and "Denied" in str(error.value)
    assert not list((tmp_path / "private").glob("*.url"))
