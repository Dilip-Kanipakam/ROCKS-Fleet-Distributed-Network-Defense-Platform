from __future__ import annotations

import os
from dataclasses import dataclass

from rocks.dashboard.auth import DashboardAuthConfig


@dataclass(frozen=True)
class DashboardConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8000
    auth: DashboardAuthConfig = DashboardAuthConfig("", "", "")


def get_dashboard_config() -> DashboardConfig:
    return DashboardConfig(
        enabled=os.getenv("ROCKS_DASHBOARD_ENABLED", "true").lower() == "true",
        host=os.getenv("ROCKS_DASHBOARD_HOST", "127.0.0.1"),
        port=int(os.getenv("ROCKS_DASHBOARD_PORT", "8000")),
        auth=DashboardAuthConfig(
            username=os.getenv("ROCKS_ADMIN_USERNAME", ""),
            password_hash=os.getenv("ROCKS_ADMIN_PASSWORD_HASH", ""),
            session_secret=os.getenv("ROCKS_SESSION_SECRET", ""),
            cookie_secure=os.getenv("ROCKS_SESSION_COOKIE_SECURE", "false").lower() == "true",
        ),
    )
