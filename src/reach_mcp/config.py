"""Configuration and safety policy (TOML)."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

def default_home(
    module_file: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    windows: bool | None = None,
) -> Path:
    """Choose writable state storage for a checkout or an installed package."""
    env = os.environ if environ is None else environ
    override = env.get("REACH_MCP_HOME")
    if override:
        return Path(os.path.expandvars(override)).expanduser().resolve()
    module = Path(module_file or __file__).resolve()
    checkout = module.parents[2]
    if (checkout / "pyproject.toml").is_file():
        return checkout
    if windows is None:
        windows = os.name == "nt"
    if windows:
        local = env.get("LOCALAPPDATA")
        return (Path(local).expanduser() if local else Path.home() / "AppData" / "Local") / "ReachMCP"
    return Path.home() / ".reach-mcp"


# Also used by the launcher for .state; installed packages must not write into site-packages.
PROJECT_ROOT = default_home()
DEFAULT_CONFIG = PROJECT_ROOT / "config.toml"


@dataclass
class ScreenshotConfig:
    max_long_edge: int = 1568  # downscale so models see legible, cheap images
    format: str = "png"  # png | jpeg
    jpeg_quality: int = 80
    draw_cursor: bool = True


@dataclass
class SafetyConfig:
    failsafe_corner: bool = True  # refuse input while the cursor sits in the primary top-left corner
    pause_file: Path = field(default_factory=lambda: PROJECT_ROOT / "PAUSED")  # if this file exists, all input tools refuse
    action_delay_ms: int = 80  # settle time after each input action
    max_type_chars: int = 500
    max_wait_seconds: float = 30.0


@dataclass
class LaunchConfig:
    enabled: bool = True
    allowed: list[str] = field(default_factory=list)  # empty = any target


@dataclass
class AuditConfig:
    enabled: bool = True
    path: Path = field(default_factory=lambda: PROJECT_ROOT / "logs" / "audit.jsonl")
    log_typed_text: bool = False  # False: record only length and sha256 of typed/clipboard text


@dataclass
class HttpConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    token_env: str = "REACH_MCP_TOKEN"


@dataclass
class Config:
    screenshot: ScreenshotConfig = field(default_factory=ScreenshotConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    launch: LaunchConfig = field(default_factory=LaunchConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    disabled_tools: list[str] = field(default_factory=list)
    source: Path | None = None


def _resolve(p: str | Path) -> Path:
    p = Path(os.path.expandvars(str(p))).expanduser()
    return p if p.is_absolute() else PROJECT_ROOT / p


def _apply(obj, table: dict, section: str) -> None:
    for key, value in table.items():
        if not hasattr(obj, key):
            raise ValueError(f"unknown config key [{section}].{key}")
        current = getattr(obj, key)
        if isinstance(current, Path):
            value = _resolve(value)
        setattr(obj, key, value)


def load(path: str | Path | None = None) -> Config:
    explicit = path or os.environ.get("REACH_MCP_CONFIG")
    cfg_path = _resolve(explicit) if explicit else DEFAULT_CONFIG
    cfg = Config()
    if not cfg_path.exists():
        if explicit:
            raise FileNotFoundError(f"config file not found: {cfg_path}")
        return cfg
    with cfg_path.open("rb") as f:
        data = tomllib.load(f)
    sections = {
        "screenshot": cfg.screenshot,
        "safety": cfg.safety,
        "launch": cfg.launch,
        "audit": cfg.audit,
        "http": cfg.http,
    }
    for name, table in data.items():
        if name == "tools":
            cfg.disabled_tools = list(table.get("disabled", []))
        elif name in sections:
            _apply(sections[name], table, name)
        else:
            raise ValueError(f"unknown config section [{name}]")
    if cfg.screenshot.format not in ("png", "jpeg"):
        raise ValueError("[screenshot].format must be 'png' or 'jpeg'")
    cfg.source = cfg_path
    return cfg
