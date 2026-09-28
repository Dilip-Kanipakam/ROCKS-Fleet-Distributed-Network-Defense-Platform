from __future__ import annotations

from datetime import datetime, timezone

from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.hub.registry import EdgeRegistry
from rocks.hub.service import HubService
from rocks.hub.storage import HubStorage
from rocks.ml.analysis import analyze_behavior_summary


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


def test_analysis_is_unique_by_telemetry_and_model(tmp_path):
    storage = HubStorage(tmp_path / "hub.db")
    record = make_record()
    storage.insert_telemetry(record)
    result = analyze_behavior_summary(
        record,
        expected_traffic=None,
        baseline_status="NOT_READY",
        analyzed_at="2026-01-01T00:00:00Z",
    )
    assert storage.insert_analysis(result) is True
    assert storage.insert_analysis(result) is False
    stored = storage.get_analysis(record.record_id, result.model_version)
    assert stored is not None
    assert stored.baseline_status == "BASELINE_NOT_READY"


def test_ml_failure_does_not_break_telemetry_ingestion(tmp_path):
    storage = HubStorage(tmp_path / "hub.db")
    service = HubService(storage)
    service.registry.register("EDGE-01")

    class FailingML:
        def analyze_and_store(self, _record):
            raise RuntimeError("synthetic ML failure")

    service.ml = FailingML()
    assert service.ingest(make_record()) is True
    assert storage.count() == 1
