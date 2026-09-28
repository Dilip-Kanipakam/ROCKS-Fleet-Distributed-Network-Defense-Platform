from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.example.yaml"


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    if yaml is None:
        raise RuntimeError("PyYAML is required to load configuration files.")

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError("Configuration root must be a mapping.")

    return data


def get_config_path() -> str:
    env_path = os.getenv("ROCKS_CONFIG_PATH")
    if env_path:
        return env_path
    return str(DEFAULT_CONFIG_PATH)
