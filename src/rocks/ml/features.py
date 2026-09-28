from __future__ import annotations

from datetime import datetime
from typing import Any

from rocks.edge.telemetry import TelemetryRecord

FEATURE_NAMES = (
    "hour",
    "day_of_week",
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "traffic_rate",
    "connection_count",
    "active_connections",
    "unique_destination_ip_count",
    "repeated_destination_count",
    "dns_request_count",
    "dns_failure_count",
    "reconnect_count",
    "connection_failure_count",
)


def behavior_summary_features(record: TelemetryRecord) -> dict[str, float]:
    if record.event_type != "BEHAVIOR_SUMMARY":
        raise ValueError("ML features require a BEHAVIOR_SUMMARY record")
    try:
        timestamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Telemetry timestamp is not valid ISO-8601") from exc
    payload = record.payload
    return {
        "hour": float(timestamp.hour),
        "day_of_week": float(timestamp.weekday()),
        "packet_count": _number(payload, "packet_count"),
        "bytes_sent": _number(payload, "bytes_sent"),
        "bytes_received": _number(payload, "bytes_received"),
        "traffic_rate": _number(payload, "traffic_rate"),
        "connection_count": _number(payload, "connection_count"),
        "active_connections": _number(payload, "active_connections"),
        "unique_destination_ip_count": _number(payload, "unique_destination_ip_count"),
        "repeated_destination_count": _number(payload, "repeated_destination_count"),
        "dns_request_count": _number(payload, "dns_request_count"),
        "dns_failure_count": _number(payload, "dns_failure_count"),
        "reconnect_count": _number(payload, "reconnect_count"),
        "connection_failure_count": _number(payload, "connection_failure_count"),
    }


def actual_traffic(record: TelemetryRecord) -> float:
    features = behavior_summary_features(record)
    return max(0.0, features["bytes_sent"] + features["bytes_received"])


def _number(payload: dict[str, Any], key: str) -> float:
    value = payload.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return max(0.0, float(value))
