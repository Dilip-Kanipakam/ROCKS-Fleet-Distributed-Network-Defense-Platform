from __future__ import annotations

import os
import math
from dataclasses import dataclass

from rocks.config import load_config


@dataclass(frozen=True)
class AlertConfig:
    enabled: bool = True
    anomaly_threshold: float = 0.70
    high_retention_threshold: float = 0.70


def get_alert_config() -> AlertConfig:
    values = load_config().get("alerts", {})
    if not isinstance(values, dict):
        raise ValueError("alerts configuration must be a mapping")
    enabled = values.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("alerts.enabled must be true or false")
    thresholds: dict[str, float] = {}
    for name in ("anomaly_threshold", "high_retention_threshold"):
        raw_value = values.get(name, 0.70)
        if isinstance(raw_value, bool):
            raise ValueError(f"alerts.{name} must be a finite number between 0 and 1")
        try:
            numeric = float(raw_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"alerts.{name} must be a finite number between 0 and 1") from exc
        if not math.isfinite(numeric) or not 0 <= numeric <= 1:
            raise ValueError(f"alerts.{name} must be a finite number between 0 and 1")
        thresholds[name] = numeric
    return AlertConfig(
        enabled=enabled,
        anomaly_threshold=thresholds["anomaly_threshold"],
        high_retention_threshold=thresholds["high_retention_threshold"],
    )


@dataclass(frozen=True)
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    sender: str = ""
    recipients: str = ""
    minimum_severity: str = "HIGH"
    starttls: bool = True
    use_ssl: bool = False
    timeout_seconds: float = 5.0

    def __repr__(self) -> str:
        username_state = "configured" if self.username else "empty"
        password_state = "configured" if self.password else "empty"
        recipient_state = "configured" if self.recipients else "empty"
        sender_state = "configured" if self.sender else "empty"
        return (
            "EmailConfig("
            f"enabled={self.enabled!r}, smtp_host={self.smtp_host!r}, smtp_port={self.smtp_port!r}, "
            f"username={username_state!r}, password={password_state!r}, "
            f"sender={sender_state!r}, recipients={recipient_state!r}, "
            f"minimum_severity={self.minimum_severity!r}, starttls={self.starttls!r}, "
            f"use_ssl={self.use_ssl!r}, timeout_seconds={self.timeout_seconds!r})"
        )


def get_email_config() -> EmailConfig:
    values = load_config().get("email", {})
    if not isinstance(values, dict):
        values = {}
    try:
        smtp_port = int(os.getenv("ROCKS_SMTP_PORT", str(values.get("smtp_port", 587))))
    except (TypeError, ValueError):
        smtp_port = -1
    try:
        timeout_seconds = float(os.getenv("ROCKS_SMTP_TIMEOUT_SECONDS", str(values.get("timeout_seconds", 5))))
    except (TypeError, ValueError):
        timeout_seconds = -1
    return EmailConfig(
        enabled=os.getenv("ROCKS_EMAIL_ENABLED", str(values.get("enabled", False))).lower() == "true",
        smtp_host=os.getenv("ROCKS_SMTP_HOST", str(values.get("smtp_host", ""))).strip(),
        smtp_port=smtp_port,
        username=os.getenv("ROCKS_SMTP_USERNAME", str(values.get("username", ""))),
        password=os.getenv("ROCKS_SMTP_PASSWORD", str(values.get("password", ""))),
        sender=os.getenv("ROCKS_SMTP_FROM", str(values.get("from", ""))).strip(),
        recipients=os.getenv("ROCKS_SMTP_TO", str(values.get("to", ""))).strip(),
        minimum_severity=os.getenv("ROCKS_EMAIL_MINIMUM_SEVERITY", str(values.get("minimum_severity", "HIGH"))).upper(),
        starttls=os.getenv("ROCKS_SMTP_STARTTLS", str(values.get("starttls", True))).lower() == "true",
        use_ssl=os.getenv("ROCKS_SMTP_USE_SSL", str(values.get("use_ssl", False))).lower() == "true",
        timeout_seconds=timeout_seconds,
    )
