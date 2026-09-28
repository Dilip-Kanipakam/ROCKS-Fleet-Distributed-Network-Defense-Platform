from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from rocks.edge.features import TrafficFeatures
from rocks.edge.flow import FlowRecord
from rocks.edge.telemetry import (
    SCHEMA_VERSION,
    TelemetryRecord,
    behavior_summary_telemetry,
    connection_telemetry,
    dns_telemetry,
    reconnect_telemetry,
    telemetry_from_dict,
    telemetry_from_json,
    telemetry_to_dict,
    telemetry_to_json,
)


def features() -> TrafficFeatures:
    return TrafficFeatures(0.0, 60.0, 3, 300, 200, 100, 2, 1, 2, 3, 1, 1, 1, 1, 1, 5.0, 0.05, "192.0.2.1|aa")


def test_common_envelope_and_json_round_trip():
    record = behavior_summary_telemetry(
        features(),
        "ROCKS-EDGE-01",
        timestamp=datetime(2026, 9, 27, 18, 30, 15, tzinfo=timezone.utc),
    )
    data = telemetry_to_dict(record)
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["timestamp"] == "2026-09-27T18:30:15Z"
    assert data["sensor_id"] == "ROCKS-EDGE-01"
    assert data["device_id"] == "192.0.2.1|aa"
    assert data["event_type"] == "BEHAVIOR_SUMMARY"
    assert telemetry_from_json(telemetry_to_json(record)) == record
    assert json.loads(telemetry_to_json(record))["payload"]["packet_count"] == 3


def test_event_types_and_payloads():
    flow = FlowRecord("192.0.2.1", "198.51.100.1", 1234, 443, "TCP", 10.0, 12.0, 2, 150)
    connection = connection_telemetry(flow, "SENSOR", "DEVICE", source_mac="aa")
    dns = dns_telemetry("SENSOR", source_ip="192.0.2.1", source_port=50000, destination_ip="198.51.100.53", destination_port=53, request_count=2)
    reconnect = reconnect_telemetry("SENSOR", reconnect_count=2, connection_failure_count=1)
    assert connection.event_type == "CONNECTION"
    assert connection.payload["connection_duration_ms"] == 2000.0
    assert connection.payload["source"]["mac"] == "aa"
    assert dns.event_type == "DNS"
    assert dns.payload["request_count"] == 2
    assert reconnect.event_type == "RECONNECT"
    assert reconnect.payload["connection_failure_count"] == 1


def test_duplicate_record_id_is_stable():
    first = behavior_summary_telemetry(features(), "SENSOR", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    second = behavior_summary_telemetry(features(), "SENSOR", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert first.record_id == second.record_id


def test_malformed_telemetry_is_rejected():
    with pytest.raises(ValueError):
        telemetry_from_dict({"schema_version": SCHEMA_VERSION})
    with pytest.raises(ValueError):
        telemetry_from_json("[]")
    with pytest.raises(ValueError):
        TelemetryRecord("SENSOR", None, "UNKNOWN", {})


def test_payload_does_not_contain_packet_content():
    record = behavior_summary_telemetry(features(), "SENSOR")
    assert "payload" not in json.dumps(record.payload).lower()
