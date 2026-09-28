from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from rocks.edge.features import TrafficFeatures
from rocks.edge.storage import TelemetryStorage
from rocks.edge.telemetry import behavior_summary_telemetry, dns_telemetry


def record(sensor: str = "SENSOR", timestamp: datetime | None = None):
    features = TrafficFeatures(0.0, 60.0, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0)
    return behavior_summary_telemetry(features, sensor, device_id="DEVICE", timestamp=timestamp)


def test_sqlite_storage_lifecycle_and_indexes(tmp_path):
    path = tmp_path / "nested" / "telemetry.db"
    storage = TelemetryStorage(path)
    storage.initialize()
    first = record(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    second = dns_telemetry("SENSOR", source_ip="192.0.2.1", source_port=1, destination_ip="198.51.100.53", destination_port=53, request_count=1, timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert storage.insert_telemetry(first) is True
    assert storage.insert_telemetry(first) is False
    assert storage.insert_telemetry(second) is True
    assert storage.count() == 2
    assert storage.get_recent(1)[0].record_id == second.record_id
    assert storage.get_by_device("DEVICE")[0].record_id == first.record_id
    assert storage.get_by_event_type("DNS")[0].record_id == second.record_id
    assert len(storage.get_since("2026-01-02T00:00:00+00:00")) == 1
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(telemetry)")}
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(telemetry)")}
    assert {"id", "payload_json", "retention_priority", "retention_reason"} <= columns
    assert {"idx_telemetry_timestamp", "idx_telemetry_sensor_id", "idx_telemetry_device_id", "idx_telemetry_event_type"} <= indexes


def test_delete_before_and_payload_only_metadata(tmp_path):
    storage = TelemetryStorage(tmp_path / "telemetry.db")
    old = record(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    new = record(timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc))
    storage.insert_many([old, new])
    assert storage.delete_before("2026-01-02T00:00:00+00:00") == 1
    assert storage.count() == 1
    assert "secret payload" not in str(storage.get_recent()[0].payload)
