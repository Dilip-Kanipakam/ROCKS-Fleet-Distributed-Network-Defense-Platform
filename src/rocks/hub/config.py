from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rocks.paths import data_dir
from rocks.config import get_hub_path
from rocks.config import load_config


@dataclass(frozen=True)
class HubConfig:
    enabled: bool = False
    url: str = ""
    api_key: str = ""
    host: str = "127.0.0.1"
    port: int = 8000
    database_path: Path = data_dir() / "rocks-hub.db"
    timeout_seconds: float = 10.0
    edge_liveness_timeout_seconds: int = 60


def get_hub_config() -> HubConfig:
    config = load_config()
    hub = config.get("hub", {})
    return HubConfig(
        enabled=bool(hub.get("enabled", False)),
        url=str(hub.get("url", "")),
        api_key=str(hub.get("api_key", "")),
        timeout_seconds=float(hub.get("timeout_seconds", 10)),
        edge_liveness_timeout_seconds=max(1, int(hub.get("edge_liveness_timeout_seconds", 60))),
        database_path=get_hub_path(),
    )
