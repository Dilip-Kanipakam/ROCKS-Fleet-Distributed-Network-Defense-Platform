from __future__ import annotations

from datetime import datetime, timezone

from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.hub.registry import EdgeRegistry
from rocks.hub.storage import HubStorage


def make_record(sensor_id: str = "EDGE-01"):
    features = TrafficFeatures(0, 60, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0)
    return behavior_summary_telemetry(features, sensor_id, device_id="DEVICE-01", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_hub_storage_persists_registry_and_telemetry(tmp_path):
    path = tmp_path / "hub.db"
    storage = HubStorage(path)
    registry = EdgeRegistry(storage)
    edge, api_key = registry.register("EDGE-01", "Lab Edge")
    record = make_record()
    assert api_key
    assert storage.insert_telemetry(record) is True
    reopened = HubStorage(path)
    assert reopened.count() == 1
    assert reopened.get_telemetry(record.record_id).record_id == record.record_id
    assert reopened.get_edge(edge.sensor_id).name == "Lab Edge"
    assert reopened.insert_telemetry(record) is False
    assert reopened.event_type_counts() == {"BEHAVIOR_SUMMARY": 1}
