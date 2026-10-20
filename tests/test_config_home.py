from pathlib import Path

from reach_mcp import config


def test_checkout_keeps_state_with_source(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    module = checkout / "src" / "reach_mcp" / "config.py"
    assert config.default_home(module, {}) == checkout


def test_installed_package_uses_local_appdata(tmp_path):
    module = tmp_path / "venv" / "Lib" / "site-packages" / "reach_mcp" / "config.py"
    local = tmp_path / "user-data"
    home = config.default_home(module, {"LOCALAPPDATA": str(local)}, windows=True)
    assert home == local / "ReachMCP"
    assert not home.is_relative_to(tmp_path / "venv")


def test_home_override_takes_precedence(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pyproject.toml").touch()
    override = tmp_path / "private-data"
    module = checkout / "src" / "reach_mcp" / "config.py"
    assert config.default_home(module, {"REACH_MCP_HOME": str(override)}) == override


def test_non_windows_fallback(tmp_path):
    module = tmp_path / "installed" / "package" / "config.py"
    assert config.default_home(module, {}, windows=False) == Path.home() / ".reach-mcp"


def test_config_paths_use_data_home(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(config, "DEFAULT_CONFIG", tmp_path / "config.toml")
    monkeypatch.delenv("REACH_MCP_CONFIG", raising=False)
    (tmp_path / "settings.toml").write_text(
        '[audit]\npath = "private/audit.jsonl"\n[safety]\npause_file = "HALT"\n',
        encoding="utf-8",
    )
    cfg = config.load("settings.toml")
    assert cfg.audit.path == tmp_path / "private" / "audit.jsonl"
    assert cfg.safety.pause_file == tmp_path / "HALT"
    assert config.AuditConfig().path == tmp_path / "logs" / "audit.jsonl"
    assert config.SafetyConfig().pause_file == tmp_path / "PAUSED"

def test_first_run_without_audit_creates_default_workspace(tmp_path, monkeypatch):
    import asyncio
    from reach_mcp import config
    from reach_mcp.approval import ApprovalGate
    from reach_mcp.server import build_server

    state = tmp_path / "new-installed-state"
    monkeypatch.setattr(config, "PROJECT_ROOT", state)
    cfg = config.Config()
    cfg.audit.enabled = False
    cfg.execution.enabled = False
    server = build_server(cfg, approval_gate=ApprovalGate(policy="client"))
    result = asyncio.run(server.call_tool("reach_list_directory", {}))
    assert state.is_dir()
    assert not result.is_error
