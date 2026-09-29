from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.yaml"
DEFAULT_CONFIG_TEMPLATE_PATH = CONFIG_DIR / "config.example.yaml"


def build_default_config() -> dict[str, Any]:
    template_path = DEFAULT_CONFIG_TEMPLATE_PATH
    if template_path.exists():
        return load_config(template_path)

    return {
        "project": {"name": "ROCKS Fleet", "version": "0.1.0"},
        "deployment": {"mode": "all-in-one"},
        "edge": {
            "enabled": True,
            "sensor_id": "ROCKS-EDGE-01",
            "interface": "",
            "capture_mode": "live",
            "hub_url": "",
            "send_interval_seconds": 5,
            "buffer_limit": 10000,
        },
        "hub": {
            "enabled": False,
            "url": "",
            "api_key": "",
            "timeout_seconds": 10,
            "edge_liveness_timeout_seconds": 60,
        },
        "telemetry": {"interval_seconds": 60, "window_seconds": 60},
        "health": {"telemetry_freshness_seconds": 300},
        "storage": {"database": "", "buffer": "", "hub_database": ""},
        "ml": {"enabled": False, "model_path": "data/ml/rocks_baseline.joblib", "minimum_samples": 20, "model_version": "rocks-baseline-v1"},
        "dashboard": {"enabled": True, "session_secret": "", "admin_username": "", "admin_password_hash": ""},
        "alerts": {"enabled": True, "anomaly_threshold": 0.70, "high_retention_threshold": 0.70},
        "email": {
            "enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "from": "",
            "to": "",
            "minimum_severity": "HIGH",
            "starttls": True,
            "use_ssl": False,
            "timeout_seconds": 5,
        },
    }


def write_config(config: dict[str, Any], config_path: str | Path | None = None) -> Path:
    path = Path(config_path) if config_path is not None else Path(get_config_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    if yaml is None:
        raise RuntimeError("PyYAML is required to write configuration files.")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, sort_keys=False, default_flow_style=False)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return path


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    if config_path is None:
        config_path = get_config_path()

    path = Path(config_path)
    if path == DEFAULT_CONFIG_PATH and not path.exists() and DEFAULT_CONFIG_TEMPLATE_PATH.exists():
        path = DEFAULT_CONFIG_TEMPLATE_PATH
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
