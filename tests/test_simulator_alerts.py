from __future__ import annotations

from datetime import datetime, timezone

from rocks.alerts.engine import AlertEngine
from rocks.hub.storage import HubStorage
from rocks.ml.analysis import analyze_behavior_summary
from rocks.simulator.generator import Scenario, generate_records


def test_simulator_scenarios_are_safe_and_typed():
    for scenario in Scenario:
        records = generate_records(scenario, count=2)
        assert len(records) == 2
        assert all(record.sensor_id == "ROCKS-SIM-01" for record in records)
    deauth = generate_records(Scenario.DEAUTH_RELATED_SIMULATION)[0]
    assert deauth.payload["simulation"] is True
    assert deauth.payload["simulation_type"] == "DEAUTH_RELATED_SIMULATION"


def test_alert_thresholds_and_structure():
    normal = generate_records(Scenario.NORMAL)[0]
    spike = generate_records(Scenario.HIGH_TRAFFIC)[0]
    normal_analysis = analyze_behavior_summary(normal, expected_traffic=1000, baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    spike_analysis = analyze_behavior_summary(spike, expected_traffic=1000, baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    engine = AlertEngine()
    assert engine.create_alert(normal_analysis) is None
    alert = engine.create_alert(spike_analysis)
    assert alert is not None
    assert alert.alert_type == "POTENTIAL_ANOMALY"
    assert alert.severity == "HIGH"
    assert alert.status == "OPEN"
    assert "attack" not in alert.message.lower()


def test_alert_persistence_and_duplicate_prevention(tmp_path):
    storage = HubStorage(tmp_path / "hub.db")
    record = generate_records(Scenario.HIGH_TRAFFIC)[0]
    storage.insert_telemetry(record)
    analysis = analyze_behavior_summary(record, expected_traffic=1000, baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    alert = AlertEngine().create_alert(analysis)
    assert alert is not None
    assert storage.insert_alert(alert) is True
    assert storage.insert_alert(alert) is False
    assert storage.alert_counts()["high"] == 1
    assert storage.recent_alerts()[0]["telemetry_id"] == record.record_id
