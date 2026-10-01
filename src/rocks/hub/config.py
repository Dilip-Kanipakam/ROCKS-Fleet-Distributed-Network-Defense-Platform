from __future__ import annotations

import os
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
    admin_api_key: str = ""
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
        url=os.getenv("ROCKS_HUB_URL", str(hub.get("url", ""))),
        api_key=os.getenv("ROCKS_API_KEY", str(hub.get("api_key", ""))),
        admin_api_key=os.getenv("ROCKS_ADMIN_API_KEY", str(hub.get("admin_api_key", ""))),
        host=str(hub.get("host", "127.0.0.1")),
        port=int(hub.get("port", 8000)),
        timeout_seconds=float(hub.get("timeout_seconds", 10)),
        edge_liveness_timeout_seconds=max(1, int(hub.get("edge_liveness_timeout_seconds", 60))),
        database_path=get_hub_path(),
    )
