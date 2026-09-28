from __future__ import annotations

from dataclasses import dataclass

from rocks.config import load_config


@dataclass(frozen=True)
class AlertConfig:
    enabled: bool = True
    anomaly_threshold: float = 0.70
    high_retention_threshold: float = 0.70


def get_alert_config() -> AlertConfig:
    values = load_config().get("alerts", {})
    return AlertConfig(
        enabled=bool(values.get("enabled", True)),
        anomaly_threshold=float(values.get("anomaly_threshold", 0.70)),
        high_retention_threshold=float(values.get("high_retention_threshold", 0.70)),
    )
