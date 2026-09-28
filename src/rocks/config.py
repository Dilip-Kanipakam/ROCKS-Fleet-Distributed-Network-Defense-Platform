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


def get_storage_path(config_path: str | Path | None = None) -> Path:
    config = load_config(config_path)
    configured_path = config.get("storage", {}).get("database")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "rocks-edge.db"


def get_buffer_path(config_path: str | Path | None = None) -> Path:
    config = load_config(config_path)
    configured_path = config.get("storage", {}).get("buffer")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "rocks-edge-buffer.db"


def get_hub_path(config_path: str | Path | None = None) -> Path:
    config = load_config(config_path)
    configured_path = config.get("storage", {}).get("hub_database")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "rocks-hub.db"


def get_edge_agent_config(config_path: str | Path | None = None) -> dict[str, Any]:
    config = load_config(config_path)
    edge = config.get("edge", {})
    telemetry = config.get("telemetry", {})
    return {
        "sensor_id": os.getenv("ROCKS_SENSOR_ID", str(edge.get("sensor_id", "ROCKS-EDGE-01"))),
        "interface": os.getenv("ROCKS_INTERFACE", str(edge.get("interface", ""))),
        "hub_url": os.getenv("ROCKS_HUB_URL", str(edge.get("hub_url", config.get("hub", {}).get("url", "")))),
        "api_key": os.getenv("ROCKS_API_KEY", str(config.get("hub", {}).get("api_key", ""))),
        "send_interval_seconds": float(edge.get("send_interval_seconds", 5)),
        "buffer_limit": int(edge.get("buffer_limit", 10_000)),
        "telemetry_window_seconds": float(telemetry.get("window_seconds", 60)),
    }
