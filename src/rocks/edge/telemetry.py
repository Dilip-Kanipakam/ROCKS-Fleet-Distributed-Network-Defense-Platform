from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from rocks.edge.features import TrafficFeatures
from rocks.edge.flow import FlowRecord

SCHEMA_VERSION = "1.0"
EVENT_TYPES = {"CONNECTION", "DNS", "RECONNECT", "BEHAVIOR_SUMMARY"}
_TELEMETRY_NAMESPACE = uuid.UUID("e0a5f7b7-3c52-4d90-8e98-1f1573c27c5a")


def utc_timestamp(timestamp: datetime | None = None) -> str:
    value = timestamp or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _stable_id(envelope: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    content = json.dumps(
        {"envelope": envelope, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    )
    return str(uuid.uuid5(_TELEMETRY_NAMESPACE, content))


@dataclass(frozen=True)
class TelemetryRecord:
    sensor_id: str
    device_id: str | None
    event_type: str
    payload: dict[str, Any]
    timestamp: str = field(default_factory=utc_timestamp)
    schema_version: str = SCHEMA_VERSION
    record_id: str = ""
    retention_priority: int | None = None
    retention_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.sensor_id:
            raise ValueError("sensor_id is required")
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"Unsupported telemetry event type: {self.event_type}")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"Unsupported telemetry schema version: {self.schema_version}")
        if not self.record_id:
            envelope = {
                "schema_version": self.schema_version,
                "timestamp": self.timestamp,
                "sensor_id": self.sensor_id,
                "device_id": self.device_id,
                "event_type": self.event_type,
            }
            object.__setattr__(self, "record_id", _stable_id(envelope, self.payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "sensor_id": self.sensor_id,
            "device_id": self.device_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "retention_priority": self.retention_priority,
            "retention_reason": self.retention_reason,
        }


def telemetry_to_dict(record: TelemetryRecord) -> dict[str, Any]:
    return record.to_dict()


def telemetry_to_json(record: TelemetryRecord) -> str:
    return json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))


def telemetry_from_dict(data: Mapping[str, Any]) -> TelemetryRecord:
    required = {"schema_version", "timestamp", "sensor_id", "device_id", "event_type", "payload"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"Telemetry is missing required fields: {sorted(missing)}")
    if not isinstance(data["payload"], dict):
        raise ValueError("Telemetry payload must be an object")
    return TelemetryRecord(
        record_id=str(data.get("record_id", "")),
        schema_version=str(data["schema_version"]),
        timestamp=str(data["timestamp"]),
        sensor_id=str(data["sensor_id"]),
        device_id=data["device_id"],
        event_type=str(data["event_type"]),
        payload=dict(data["payload"]),
        retention_priority=data.get("retention_priority"),
        retention_reason=data.get("retention_reason"),
    )


def telemetry_from_json(value: str) -> TelemetryRecord:
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("Telemetry is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("Telemetry JSON root must be an object")
    return telemetry_from_dict(data)


def connection_telemetry(
    flow: FlowRecord,
    sensor_id: str,
    device_id: str | None = None,
    *,
    source_mac: str | None = None,
    bytes_sent: int | None = None,
    bytes_received: int | None = None,
    timestamp: datetime | None = None,
) -> TelemetryRecord:
    payload = {
        "source": {"ip": flow.source_ip, "mac": source_mac, "port": flow.source_port},
        "destination": {"ip": flow.destination_ip, "port": flow.destination_port},
        "protocol": flow.protocol,
        "packet_count": flow.packet_count,
        "bytes_sent": flow.bytes if bytes_sent is None else bytes_sent,
        "bytes_received": bytes_received,
        "connection_duration_ms": round(flow.duration * 1000, 3),
    }
    return TelemetryRecord(sensor_id, device_id, "CONNECTION", payload, timestamp=utc_timestamp(timestamp))


def dns_telemetry(
    sensor_id: str,
    *,
    source_ip: str,
    source_port: int | None,
    destination_ip: str,
    destination_port: int | None,
    request_count: int,
    failure_count: int = 0,
    device_id: str | None = None,
    protocol: str | None = None,
    timestamp: datetime | None = None,
) -> TelemetryRecord:
    payload = {
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol or ("UDP" if destination_port == 53 else "DNS"),
        "request_count": request_count,
        "failure_count": failure_count,
    }
    return TelemetryRecord(sensor_id, device_id, "DNS", payload, timestamp=utc_timestamp(timestamp))


def reconnect_telemetry(
    sensor_id: str,
    *,
    reconnect_count: int,
    connection_failure_count: int,
    device_id: str | None = None,
    timestamp: datetime | None = None,
) -> TelemetryRecord:
    payload = {
        "reconnect_count": reconnect_count,
        "connection_failure_count": connection_failure_count,
    }
    return TelemetryRecord(sensor_id, device_id, "RECONNECT", payload, timestamp=utc_timestamp(timestamp))


def behavior_summary_telemetry(
    features: TrafficFeatures,
    sensor_id: str,
    *,
    device_id: str | None = None,
    window_seconds: float = 60.0,
    repeated_destination_count: int | None = None,
    dns_failure_count: int = 0,
    reconnect_count: int = 0,
    connection_failure_count: int = 0,
    timestamp: datetime | None = None,
) -> TelemetryRecord:
    """Build a schema 1.0 BEHAVIOR_SUMMARY record from window features.

    ``bytes_sent`` is traffic from the summarized source toward destinations.
    ``bytes_received`` is traffic from destinations toward the summarized source.
    ``dns_request_count`` is the count of DNS-related packets in the window, not
    a parsed DNS opcode. ``dns_failure_count``, ``reconnect_count``, and
    ``connection_failure_count`` stay at the supplied defaults unless the caller
    observed those events; the live Edge path does not invent them.
    """

    payload = {
        "window_seconds": window_seconds,
        "packet_count": features.packet_count,
        "bytes_sent": features.bytes_sent,
        "bytes_received": features.bytes_received,
        "traffic_rate": features.traffic_rate,
        "request_rate": features.packet_rate,
        "connection_count": features.connection_count,
        "active_connections": features.active_flow_count,
        "unique_destination_ip_count": features.unique_destination_ip_count,
        "repeated_destination_count": (
            features.repeated_destination_count if repeated_destination_count is None else repeated_destination_count
        ),
        "dns_request_count": features.dns_packet_count,
        "dns_failure_count": dns_failure_count,
        "reconnect_count": reconnect_count,
        "connection_failure_count": connection_failure_count,
    }
    return TelemetryRecord(sensor_id, device_id or features.device_id, "BEHAVIOR_SUMMARY", payload, timestamp=utc_timestamp(timestamp))
