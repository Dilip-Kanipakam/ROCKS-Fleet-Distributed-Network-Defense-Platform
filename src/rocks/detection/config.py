from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rocks.config import get_config_path, load_config


@dataclass(frozen=True)
class DetectionConfig:
    enabled: bool = True
    high_traffic_rate: float = 200.0
    connection_burst_rate: float = 0.5
    unique_destination_count: int = 20
    unique_destination_port_count: int = 30
    reconnect_count: int = 10
    dns_request_rate: float = 2.0
    dns_failure_rate: float = 0.3
    deauth_count: int = 1
    window_seconds: float = 60.0
    ml_anomaly_threshold: float = 0.70


def get_detection_config(config_path: str | Path | None = None) -> DetectionConfig:
    config = load_config(config_path or get_config_path())
    values = config.get("detection", {})
    if not isinstance(values, dict):
        raise ValueError("detection configuration must be a mapping")
    defaults: dict[str, Any] = DetectionConfig(
        ml_anomaly_threshold=float(config.get("alerts", {}).get("anomaly_threshold", 0.70))
    ).__dict__.copy()
    parsed: dict[str, Any] = {}
    integer_fields = {"unique_destination_count", "unique_destination_port_count", "reconnect_count", "deauth_count"}
    for name, default in defaults.items():
        raw = os.getenv(f"ROCKS_DETECTION_{name.upper()}", str(values.get(name, default)))
        if name == "enabled":
            normalized = raw.lower() if isinstance(raw, str) else str(raw).lower()
            if normalized not in {"true", "false"}:
                raise ValueError("detection.enabled must be true or false")
            parsed[name] = normalized == "true"
            continue
        try:
            numeric = float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"detection.{name} must be numeric") from exc
        if not math.isfinite(numeric) or numeric <= 0:
            raise ValueError(f"detection.{name} must be a positive finite value")
        if name in integer_fields:
            if not numeric.is_integer():
                raise ValueError(f"detection.{name} must be a positive integer")
            parsed[name] = int(numeric)
        else:
            parsed[name] = numeric
    if parsed["dns_failure_rate"] > 1 or parsed["ml_anomaly_threshold"] > 1:
        raise ValueError("detection.dns_failure_rate and detection.ml_anomaly_threshold must be at most 1")
    return DetectionConfig(**parsed)
