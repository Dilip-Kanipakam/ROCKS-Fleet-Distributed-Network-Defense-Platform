from __future__ import annotations

from datetime import datetime, timezone

import pytest

from rocks.detection.config import DetectionConfig
from rocks.detection.engine import DetectionEngine
from rocks.alerts.engine import AlertEngine
from rocks.cli import main
from rocks.hub.service import HubService
from rocks.hub.storage import HubStorage
from rocks.edge.telemetry import TelemetryRecord
from rocks.ml.analysis import AnalysisResult
from rocks.simulator.generator import Scenario, generate_records


def _record(event_type="BEHAVIOR_SUMMARY", **payload):
    defaults = {
        "window_seconds": 60,
        "traffic_rate": 10,
        "connection_count": 2,
        "unique_destination_ip_count": 2,
        "unique_destination_port_count": 2,
        "repeated_destination_count": 0,
        "dns_request_count": 0,
        "dns_failure_count": 0,
        "reconnect_count": 0,
        "connection_failure_count": 0,
    }
    defaults.update(payload)
    return TelemetryRecord(
        sensor_id="DETECTION-TEST-EDGE",
        device_id="192.0.2.10|02:00:00:00:00:01",
        event_type=event_type,
        payload=defaults,
        timestamp="2026-09-30T12:00:00Z",
    )


def _engine(**overrides):
    values = {
        "enabled": True,
        "high_traffic_rate": 200,
        "connection_burst_rate": 0.5,
        "unique_destination_count": 20,
        "unique_destination_port_count": 30,
        "reconnect_count": 10,
        "dns_request_rate": 2,
        "dns_failure_rate": 0.3,
        "deauth_count": 1,
        "window_seconds": 60,
        "ml_anomaly_threshold": 0.7,
    }
    values.update(overrides)
    return DetectionEngine(DetectionConfig(**values))


def test_normal_behavior_has_no_rule_evidence():
    assessment = _engine().assess(_record())
    assert assessment.rules_triggered == []
    assert assessment.severity == "INFO"
    assert assessment.ml_anomaly is None
    assert assessment.risk_score is None


def test_high_traffic_rule_contains_measured_evidence():
    assessment = _engine().assess(_record(traffic_rate=250))
    rule = assessment.rules_triggered[0]
    assert rule.rule_id == "HIGH_TRAFFIC"
    assert rule.evidence["traffic_rate"] == 250
    assert rule.evidence["threshold"] == 200
    assert "unusually high" in rule.reason.lower()
    assert assessment.severity == "WARNING"


def test_connection_burst_rule_uses_window_rate():
    assessment = _engine().assess(_record(connection_count=40, window_seconds=60))
    rule_ids = {rule.rule_id for rule in assessment.rules_triggered}
    assert "CONNECTION_BURST" in rule_ids
    rule = next(rule for rule in assessment.rules_triggered if rule.rule_id == "CONNECTION_BURST")
    assert rule.evidence["observed_rate"] == pytest.approx(40 / 60)


def test_reconnaissance_like_uses_careful_terminology_and_destination_evidence():
    assessment = _engine().assess(
        _record(unique_destination_ip_count=25, unique_destination_port_count=35, repeated_destination_count=8)
    )
    rule = next(rule for rule in assessment.rules_triggered if rule.rule_id == "RECONNAISSANCE_LIKE")
    assert "Reconnaissance-like" in rule.title
    assert rule.evidence["unique_destination_count"] == 25
    assert "port scan" not in rule.title.lower()


def test_dns_anomaly_detects_failure_ratio_and_request_rate():
    assessment = _engine().assess(
        _record("DNS", request_count=20, failure_count=8, window_seconds=60)
    )
    rule = next(rule for rule in assessment.rules_triggered if rule.rule_id == "DNS_ANOMALY")
    assert rule.evidence["failure_rate"] == pytest.approx(0.4)
    assert rule.evidence["request_rate"] == pytest.approx(20 / 60)
    assert "tunnel" not in rule.title.lower()


def test_reconnect_storm_uses_explicit_counts():
    assessment = _engine().assess(_record("RECONNECT", reconnect_count=12, connection_failure_count=9))
    rule = next(rule for rule in assessment.rules_triggered if rule.rule_id == "RECONNECT_STORM")
    assert rule.evidence["reconnect_count"] == 12
    assert rule.evidence["connection_failure_count"] == 9


def test_simulated_deauth_is_marked_and_real_evidence_is_gated():
    simulated = _engine().assess(
        _record(simulation=True, simulation_type="DEAUTH_RELATED_SIMULATION")
    )
    deauth = next(rule for rule in simulated.rules_triggered if rule.rule_id == "DEAUTH_RELATED")
    assert simulated.simulation is True
    assert deauth.simulation is True
    assert "simulation" in deauth.reason.lower()

    unsupported = _engine().assess(_record(deauth_count=5))
    assert "DEAUTH_RELATED" not in {rule.rule_id for rule in unsupported.rules_triggered}

    observed = _engine().assess(
        _record(deauth_count=2, management_frame_type="deauthentication", evidence_source="802.11_management_frame")
    )
    observed_rule = next(rule for rule in observed.rules_triggered if rule.rule_id == "DEAUTH_RELATED")
    assert observed_rule.simulation is False
    assert observed_rule.evidence["deauth_count"] == 2


def test_multiple_rules_aggregate_highest_existing_severity():
    assessment = _engine().assess(
        _record(
            traffic_rate=500,
            connection_count=50,
            unique_destination_ip_count=30,
            unique_destination_port_count=40,
            reconnect_count=12,
        )
    )
    assert {rule.rule_id for rule in assessment.rules_triggered} >= {
        "HIGH_TRAFFIC", "CONNECTION_BURST", "RECONNAISSANCE_LIKE", "RECONNECT_STORM"
    }
    assert assessment.severity == "HIGH"


def test_ml_signal_is_distinct_and_reuses_existing_score():
    analysis = AnalysisResult(
        telemetry_id="ml-id",
        sensor_id="sensor",
        device_id="device",
        timestamp="2026-09-30T12:00:00Z",
        model_version="rocks-baseline-v1",
        baseline_status="READY",
        actual_traffic=1000,
        expected_traffic=100,
        deviation=9,
        anomaly_score=0.82,
        retention_score=0.82,
        retention_priority="HIGH",
        analyzed_at="2026-09-30T12:00:00Z",
    )
    assessment = _engine().assess(_record(), analysis)
    assert assessment.ml_anomaly is True
    assert assessment.risk_score == 0.82
    assert assessment.severity == "HIGH"
    assert any("ML baseline" in item for item in assessment.explanation)


def test_rules_work_without_ml_and_can_be_disabled():
    assert _engine().assess(_record(traffic_rate=250), None).rules_triggered
    disabled = _engine(enabled=False).assess(_record(traffic_rate=250))
    assert disabled.rules_triggered == []
    assert disabled.severity == "INFO"


def test_thresholds_load_from_existing_yaml_and_reject_malformed_values(tmp_path):
    from rocks.config import write_config
    from rocks.detection.config import get_detection_config

    config_path = tmp_path / "config.yaml"
    write_config({"detection": {"high_traffic_rate": 333}}, config_path)
    cfg = get_detection_config(config_path)
    assert cfg.high_traffic_rate == 333
    write_config({"detection": {"high_traffic_rate": "not-number"}}, config_path)
    with pytest.raises(ValueError, match="detection.high_traffic_rate"):
        get_detection_config(config_path)
    write_config({"detection": {"reconnect_count": 2.5}}, config_path)
    with pytest.raises(ValueError, match="detection.reconnect_count"):
        get_detection_config(config_path)


def test_risk_score_is_not_invented_when_ml_unavailable():
    assessment = _engine().assess(_record(traffic_rate=250), None)
    assert assessment.risk_score is None
    assert assessment.explanation
    assert "probability" not in " ".join(assessment.explanation).lower()


def test_alert_engine_creates_evidence_alert_without_ml():
    record = _record(traffic_rate=250)
    assessment = _engine().assess(record)
    alert = AlertEngine().create_alert(None, assessment=assessment, record=record)
    assert alert is not None
    assert alert.alert_id
    assert alert.telemetry_id == record.record_id
    assert alert.status == "OPEN"
    assert alert.severity == "WARNING"
    assert alert.assessment["rules_triggered"][0]["rule_id"] == "HIGH_TRAFFIC"
    assert "unusually high" in alert.message.lower()


def test_hub_detection_runs_without_ml_and_correlates_duplicate_telemetry(tmp_path):
    storage = HubStorage(tmp_path / "hub.db")
    service = HubService(storage)
    assert service.ml is None
    record = generate_records(Scenario.HIGH_TRAFFIC, count=1)[0]

    assert service.ingest(record) is True
    assert service.ingest(record) is False

    assessments = storage.recent_detection_assessments()
    alerts = storage.recent_alerts()
    assert len(assessments) == 1
    assert len(alerts) == 1
    assert assessments[0]["assessment"]["risk_score"] is None
    assert alerts[0]["assessment"]["rules_triggered"]
    assert alerts[0]["notification_attempt_count"] == 0


def test_assessment_storage_migrates_existing_alerts_table(tmp_path):
    import sqlite3

    path = tmp_path / "previous-alert-schema.db"
    connection = sqlite3.connect(path)
    connection.execute(
        """CREATE TABLE alerts (
            alert_id TEXT PRIMARY KEY, telemetry_id TEXT NOT NULL, sensor_id TEXT NOT NULL,
            device_id TEXT, timestamp TEXT NOT NULL, alert_type TEXT NOT NULL,
            severity TEXT NOT NULL, anomaly_score REAL, retention_score REAL,
            message TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
            acknowledged_at TEXT, resolved_at TEXT
        )"""
    )
    connection.commit()
    connection.close()
    storage = HubStorage(path)
    assessment = _engine().assess(_record(traffic_rate=300))
    assert storage.insert_detection_assessment(assessment)
    row = storage.recent_detection_assessments()[0]
    assert row["assessment"]["rules_triggered"][0]["rule_id"] == "HIGH_TRAFFIC"
    assert storage.recent_alerts() == []


def test_detection_cli_status_and_synthetic_test(monkeypatch, capsys):
    monkeypatch.delenv("ROCKS_CONFIG_PATH", raising=False)
    assert main(["detection", "status"]) == 0
    status_output = capsys.readouterr().out
    assert "Deterministic detection: ENABLED" in status_output
    assert main(["detection", "test"]) == 0
    test_output = capsys.readouterr().out
    assert "high_traffic" in test_output
    assert "DEAUTH_RELATED" in test_output
    assert "SIMULATION ONLY" in test_output
    assert "no network traffic was generated" in test_output


def test_detection_cli_help():
    with pytest.raises(SystemExit) as exit_info:
        main(["detection", "--help"])
    assert exit_info.value.code == 0
