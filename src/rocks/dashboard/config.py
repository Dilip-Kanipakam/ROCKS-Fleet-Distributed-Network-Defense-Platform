from __future__ import annotations

import os
from dataclasses import dataclass

from rocks.dashboard.auth import DashboardAuthConfig
from rocks.config import load_config


@dataclass(frozen=True)
class DashboardConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8000
    auth: DashboardAuthConfig = DashboardAuthConfig("", "", "")


def get_dashboard_config() -> DashboardConfig:
    dashboard = load_config().get("dashboard", {})
    return DashboardConfig(
        enabled=os.getenv("ROCKS_DASHBOARD_ENABLED", str(dashboard.get("enabled", True))).lower() == "true",
        host=os.getenv("ROCKS_DASHBOARD_HOST", str(dashboard.get("host", "127.0.0.1"))),
        port=int(os.getenv("ROCKS_DASHBOARD_PORT", str(dashboard.get("port", 8000)))),
        auth=DashboardAuthConfig(
            username=os.getenv("ROCKS_ADMIN_USERNAME", str(dashboard.get("admin_username", ""))),
            password_hash=os.getenv("ROCKS_ADMIN_PASSWORD_HASH", str(dashboard.get("admin_password_hash", ""))),
            session_secret=os.getenv("ROCKS_SESSION_SECRET", str(dashboard.get("session_secret", ""))),
            cookie_secure=os.getenv("ROCKS_SESSION_COOKIE_SECURE", "false").lower() == "true",
        ),
    )
