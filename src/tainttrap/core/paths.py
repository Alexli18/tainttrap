"""Filesystem locations. The hook client duplicates `runtime_dir()` to stay import-free."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_MAX_SOCK_PATH = 100  # below the 104/108-byte AF_UNIX limit


def _mkdir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def home_dir() -> Path:
    return _mkdir(Path(os.environ.get("TAINTTRAP_HOME", Path.home() / ".tainttrap")).expanduser())


def config_dir() -> Path:
    default = Path.home() / ".config" / "tainttrap"
    return _mkdir(Path(os.environ.get("TAINTTRAP_CONFIG_DIR", default)).expanduser())


def runtime_dir() -> Path:
    override = os.environ.get("TAINTTRAP_RUNTIME_DIR")
    if override:
        base = Path(override).expanduser()
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches" / "tainttrap"
    elif os.environ.get("XDG_RUNTIME_DIR"):
        base = Path(os.environ["XDG_RUNTIME_DIR"]) / "tainttrap"
    else:
        base = Path(f"/tmp/tainttrap-{os.getuid()}")  # noqa: S108
    if len(str(base / "admin.sock")) > _MAX_SOCK_PATH:
        base = Path(f"/tmp/tt-{os.getuid()}")  # noqa: S108
    return _mkdir(base)


def check_socket() -> Path:
    return runtime_dir() / "check.sock"


def admin_socket() -> Path:
    return runtime_dir() / "admin.sock"


def hook_settings_file() -> Path:
    return runtime_dir() / "hook.json"


def logs_dir() -> Path:
    return _mkdir(home_dir() / "logs")


def datasets_dir() -> Path:
    return _mkdir(home_dir() / "datasets")


def models_dir() -> Path:
    return _mkdir(home_dir() / "models")


def policy_file() -> Path:
    return config_dir() / "policy.yaml"


def user_registry_file() -> Path:
    return config_dir() / "registry.yaml"
