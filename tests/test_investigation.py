from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from rocks.dashboard.auth import hash_password
from rocks.alerts.engine import Alert
from rocks.detection.engine import DetectionEngine
from rocks.detection.config import DetectionConfig
from rocks.edge.features import TrafficFeatures
from rocks.edge.flow import FlowRecord
from rocks.edge.telemetry import TelemetryRecord, behavior_summary_telemetry, connection_telemetry, dns_telemetry, telemetry_to_dict
from rocks.hub.app import create_app
from rocks.hub.storage import HubStorage
from rocks.ml.analysis import AnalysisResult, analyze_behavior_summary


def summary(sensor: str, device: str | None, timestamp: datetime, amount: int = 100):
    features = TrafficFeatures(0, 60, 2, amount, amount // 2, amount - amount // 2, 1, 1, 1, 1, 1, 1, 0, 0, 0, amount / 60, 2 / 60, device)
    return behavior_summary_telemetry(features, sensor, device_id=device, timestamp=timestamp)


def test_context_filters_related_device_source_time_and_limit(tmp_path):
    storage = HubStorage(tmp_path / "hub.db")
    first_time = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    anchor = summary("SENSOR-A", "DEVICE-A", first_time)
    second = dns_telemetry(
        "SENSOR-A", source_ip="192.0.2.10", source_port=53000,
        destination_ip="198.51.100.53", destination_port=53,
        request_count=3, device_id="DEVICE-A",
        timestamp=datetime(2026, 1, 1, 12, 1, tzinfo=timezone.utc),
    )
    other_device = summary("SENSOR-A", "DEVICE-B", datetime(2026, 1, 1, 12, 2, tzinfo=timezone.utc))
    other_sensor = summary("SENSOR-B", "DEVICE-A", datetime(2026, 1, 1, 12, 3, tzinfo=timezone.utc))
    for record in (anchor, second, other_device, other_sensor):
        storage.insert_telemetry(record)

    context = storage.telemetry_context(telemetry_id=anchor.record_id, limit=10)
    assert context["trigger"]["telemetry_id"] == anchor.record_id
    assert {item["device_id"] for item in context["related"]} == {"DEVICE-A"}
    assert [item["timestamp"] for item in context["related"]] == sorted(
        [item["timestamp"] for item in context["related"]], reverse=True
    )
    assert storage.telemetry_context(device_id="missing", limit=5)["related"] == []

    limited = storage.telemetry_context(device_id="DEVICE-A", limit=1)
    assert len(limited["related"]) == 1
    filtered = storage.telemetry_context(
        device_id="DEVICE-A", sensor_id="SENSOR-A", event_type="DNS",
        since="2026-01-01T12:00:30Z", until="2026-01-01T12:02:00Z", limit=10,
    )
    assert [item["event_type"] for item in filtered["related"]] == ["DNS"]
    by_source = storage.telemetry_context(source_ip="192.0.2.10", limit=10)
    assert len(by_source["related"]) == 1


def test_context_metadata_whitelist_excludes_payload_and_secrets(tmp_path):
    storage = HubStorage(tmp_path / "hub.db")
    record = connection_telemetry(
        FlowRecord("192.0.2.10", "198.51.100.20", 1234, 443, "TCP", 1, 3, 2, 240),
        "SENSOR-A", "DEVICE-A", source_mac="02:00:00:00:00:01", bytes_received=None,
    )
    storage.insert_telemetry(record)
    context = storage.telemetry_context(telemetry_id=record.record_id)
    metadata = context["trigger"]
    assert metadata["source_ip"] == "192.0.2.10"
    assert metadata["source_port"] == 1234
    assert metadata["destination_ip"] == "198.51.100.20"
    assert metadata["destination_port"] == 443
    assert metadata["bytes_sent"] == 240
    assert metadata["bytes_received"] is None
    assert "payload" not in metadata
    assert "api_key_hash" not in str(context)


def test_hub_context_api_auth_and_alert_linked_context(tmp_path):
    app = create_app(str(tmp_path / "hub.db"))
    service = app.state.hub_service
    _, api_key = service.registry.register("SENSOR-A")
    record = summary("SENSOR-A", "DEVICE-A", datetime(2026, 1, 1, tzinfo=timezone.utc))
    service.storage.insert_telemetry(record)
    analysis = analyze_behavior_summary(record, expected_traffic=10, baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    alert = service.alerts.create_alert(analysis)
    assert alert is not None
    service.storage.insert_alert(alert)
    client = TestClient(app)
    url = "/api/v1/telemetry/context?telemetry_id=" + record.record_id
    assert client.get(url).status_code == 401
    assert client.get(url, headers={"Authorization": "Bearer invalid"}).status_code == 401
    response = client.get(url, headers={"Authorization": f"Bearer {api_key}"})
    assert response.status_code == 200
    assert response.json()["trigger"]["telemetry_id"] == alert.telemetry_id
    assert len(response.json()["related"]) == 1
    assert client.get("/api/v1/health").status_code == 200


def test_dashboard_context_route_requires_session_and_renders_related_activity(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ROCKS_ADMIN_PASSWORD_HASH", hash_password("temporary-password"))
    monkeypatch.setenv("ROCKS_SESSION_SECRET", "temporary-session-secret")
    app = create_app(str(tmp_path / "dashboard.db"))
    record = summary("SENSOR-A", "DEVICE-A", datetime(2026, 1, 1, tzinfo=timezone.utc))
    app.state.hub_service.storage.insert_telemetry(record)
    client = TestClient(app)
    path = f"/dashboard/telemetry/{record.record_id}"
    assert client.get(path, follow_redirects=False).status_code == 303
    client.post("/dashboard/login", data={"username": "admin", "password": "temporary-password"})
    response = client.get(path)
    assert response.status_code == 200
    assert "TRIGGERING TELEMETRY" in response.text
    assert "Related recent telemetry" in response.text
    assert "DEVICE-A" in response.text
    assert "payload" not in response.text.lower()


def investigation_record(sensor_id: str, device_id: str, timestamp: str, *, event_type: str = "BEHAVIOR_SUMMARY", **payload):
    values = {"packet_count": 10, "traffic_rate": 1.0, "connection_count": 1}
    values.update(payload)
    return TelemetryRecord(sensor_id, device_id, event_type, values, timestamp=timestamp)


def investigation_client(tmp_path):
    app = create_app(str(tmp_path / "investigation.db"))
    service = app.state.hub_service
    _, api_key = service.registry.register("SENSOR-A")
    _, second_key = service.registry.register("SENSOR-B")
    return TestClient(app), service, api_key, second_key


def test_investigation_api_filters_exact_device_sensor_and_time_in_order(tmp_path):
    client, service, api_key, _ = investigation_client(tmp_path)
    device = "192.0.2.10|02:00:00:00:00:01"
    same_ip_other_device = "192.0.2.10|02:00:00:00:00:02"
    records = [
        investigation_record("SENSOR-A", device, "2026-01-01T12:00:00Z"),
        investigation_record("SENSOR-B", device, "2026-01-01T12:01:00Z"),
        investigation_record("SENSOR-A", same_ip_other_device, "2026-01-01T12:01:30Z"),
        investigation_record("SENSOR-A", device, "2026-01-01T12:02:00Z"),
        investigation_record("SENSOR-A", device, "2026-01-01T10:00:00Z"),
    ]
    for record in records:
        service.storage.insert_telemetry(record)

    headers = {"Authorization": f"Bearer {api_key}"}
    query = {"device_id": device, "start": "2026-01-01T11:00:00Z", "end": "2026-01-01T12:02:00Z"}
    response = client.get("/api/v1/investigations", params=query, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["device"]["device_id"] == device
    assert [event["timestamp"] for event in body["events"]] == [
        "2026-01-01T12:00:00Z", "2026-01-01T12:01:00Z", "2026-01-01T12:02:00Z"
    ]
    assert {event["device_id"] for event in body["events"]} == {device}
    assert all(event["event_type"] == "BEHAVIOR_SUMMARY" for event in body["events"])

    sensor_response = client.get(
        "/api/v1/investigations",
        params={**query, "sensor_id": "SENSOR-A", "start": "2026-01-01T12:00:00Z", "end": "2026-01-01T12:02:00Z"},
        headers=headers,
    )
    assert [event["sensor_id"] for event in sensor_response.json()["events"]] == ["SENSOR-A", "SENSOR-A"]
    assert len(sensor_response.json()["events"]) == 2


def test_investigation_api_auth_validation_empty_and_bounded_windows(tmp_path):
    client, _service, api_key, _ = investigation_client(tmp_path)
    headers = {"Authorization": f"Bearer {api_key}"}
    endpoint = "/api/v1/investigations"
    assert client.get(endpoint, params={"device_id": "DEVICE-A"}).status_code == 401
    assert client.get(endpoint, params={"device_id": "DEVICE-A"}, headers={"Authorization": "Bearer invalid"}).status_code == 401

    empty = client.get(endpoint, params={"device_id": "DEVICE-A"}, headers=headers)
    assert empty.status_code == 200
    assert empty.json()["events"] == []
    default_range = empty.json()["time_range"]
    assert 23 * 3600 < (datetime.fromisoformat(default_range["end"].replace("Z", "+00:00")) - datetime.fromisoformat(default_range["start"].replace("Z", "+00:00"))).total_seconds() <= 24 * 3600

    assert client.get(endpoint, params={"device_id": "bad/id"}, headers=headers).status_code == 422
    assert client.get(endpoint, params={"device_id": "DEVICE-A", "sensor_id": "bad/id"}, headers=headers).status_code == 422
    assert client.get(endpoint, params={"device_id": "DEVICE-A", "start": "yesterday"}, headers=headers).status_code == 422
    assert client.get(endpoint, params={"device_id": "DEVICE-A", "start": "2026-01-01T00:00:00"}, headers=headers).status_code == 422
    assert client.get(endpoint, params={"device_id": "DEVICE-A", "start": "2026-01-02T00:00:00Z", "end": "2026-01-01T00:00:00Z"}, headers=headers).status_code == 422

    seven_days = client.get(
        endpoint,
        params={"device_id": "DEVICE-A", "start": "2026-01-01T00:00:00Z", "end": "2026-01-08T00:00:00Z"},
        headers=headers,
    )
    assert seven_days.status_code == 200
    too_wide = client.get(
        endpoint,
        params={"device_id": "DEVICE-A", "start": "2026-01-01T00:00:00Z", "end": "2026-01-08T00:00:01Z"},
        headers=headers,
    )
    assert too_wide.status_code == 422


def test_investigation_includes_detection_ml_alert_lifecycle_and_simulation_evidence(tmp_path, monkeypatch):
    client, service, api_key, _ = investigation_client(tmp_path)
    detector = DetectionEngine(DetectionConfig())
    base_time = "2026-01-01T12:00:00Z"
    without_ml = investigation_record("SENSOR-A", "DEVICE-A", base_time, traffic_rate=250)
    with_ml = investigation_record("SENSOR-A", "DEVICE-A", "2026-01-01T12:01:00Z", traffic_rate=5)
    simulated = investigation_record(
        "SENSOR-A", "DEVICE-A", "2026-01-01T12:02:00Z",
        simulation=True, simulation_type="DEAUTH_RELATED_SIMULATION", deauth_count=3,
    )
    ordinary_telemetry = investigation_record(
        "SENSOR-A", "DEVICE-A", "2026-01-01T12:00:30Z", event_type="CONNECTION",
    )
    for record in (without_ml, with_ml, simulated, ordinary_telemetry):
        service.storage.insert_telemetry(record)

    no_ml_assessment = detector.assess(without_ml)
    ml_analysis = AnalysisResult(
        telemetry_id=with_ml.record_id, sensor_id=with_ml.sensor_id, device_id=with_ml.device_id,
        timestamp=with_ml.timestamp, model_version="test-model", baseline_status="READY",
        actual_traffic=1000, expected_traffic=100, deviation=9, anomaly_score=0.82,
        retention_score=0.82, retention_priority="HIGH", analyzed_at=with_ml.timestamp,
    )
    ml_assessment = detector.assess(with_ml, ml_analysis)
    simulation_assessment = detector.assess(simulated)
    for assessment in (no_ml_assessment, ml_assessment, simulation_assessment):
        service.storage.insert_detection_assessment(assessment)
    service.storage.insert_analysis(ml_analysis)

    alert = Alert(
        alert_id="alert-investigation-1", timestamp=without_ml.timestamp,
        telemetry_id=without_ml.record_id, sensor_id=without_ml.sensor_id,
        device_id=without_ml.device_id, alert_type="POTENTIAL_ANOMALY", severity="WARNING",
        anomaly_score=None, retention_score=None, message="Synthetic detection context.",
        status="RESOLVED", acknowledged_at="2026-01-01T12:00:40Z",
        resolved_at="2026-01-01T12:00:50Z",
    )
    service.storage.insert_alert(alert)
    monkeypatch.setattr(service.email_notifications, "send_alert", lambda *_args: pytest.fail("investigation sent email"))

    response = client.get(
        "/api/v1/investigations",
        params={"device_id": "DEVICE-A", "start": "2026-01-01T11:59:00Z", "end": "2026-01-01T12:03:00Z"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 200
    events = response.json()["events"]
    assert [event["timestamp"] for event in events] == sorted(event["timestamp"] for event in events)
    detection_events = [event for event in events if event["event_type"] == "DETECTION"]
    assert len(detection_events) == 3
    by_ref = {event["reference_id"]: event for event in detection_events}
    assert by_ref[without_ml.record_id]["details"]["ml_score"] is None
    assert by_ref[without_ml.record_id]["details"]["evidence"]
    assert by_ref[with_ml.record_id]["details"]["ml_score"] == 0.82
    deauth_event = by_ref[simulated.record_id]
    assert "simulated deauthentication" in deauth_event["title"].lower()
    assert "simulation-only" in deauth_event["reason"].lower()
    assert any(event["event_type"] == "ML_ANALYSIS" and event["details"]["model_version"] == "test-model" for event in events)
    assert {event["event_type"] for event in events} >= {
        "TELEMETRY", "BEHAVIOR_SUMMARY", "DETECTION", "ML_ANALYSIS", "ALERT",
        "ALERT_ACKNOWLEDGED", "ALERT_RESOLVED",
    }
    assert "payload" not in response.text.lower()
    assert "smtp" not in response.text.lower()


def test_case_api_create_retrieve_append_and_order_timeline(tmp_path):
    client, _service, api_key, _ = investigation_client(tmp_path)
    headers = {"Authorization": f"Bearer {api_key}"}
    response = client.post(
        "/api/v1/investigations",
        json={
            "title": "Repeated connection failures",
            "description": "Review the device activity around the alert.",
            "device_id": "DEVICE-CASE-01",
            "sensor_id": "SENSOR-A",
        },
        headers=headers,
    )
    assert response.status_code == 201
    case = response.json()
    investigation_id = case["investigation_id"]
    assert case["status"] == "OPEN"
    assert case["title"] == "Repeated connection failures"
    assert client.get(f"/api/v1/investigations/{investigation_id}", headers=headers).json() == case

    later_event = client.post(
        f"/api/v1/investigations/{investigation_id}/events",
        json={
            "timestamp": "2026-09-30T12:05:00Z",
            "event_type": "ALERT",
            "severity": "HIGH",
            "message": "High risk alert generated.",
            "source": "rocks-alerts",
            "metadata": {"alert_id": "alert-123", "telemetry_id": "telemetry-456"},
        },
        headers=headers,
    )
    earlier_event = client.post(
        f"/api/v1/investigations/{investigation_id}/events",
        json={
            "timestamp": "2026-09-30T12:04:00Z",
            "event_type": "DETECTION",
            "message": "Suspicious flow detected.",
            "metadata": {"assessment_id": "assessment-789"},
        },
        headers=headers,
    )
    assert later_event.status_code == 201
    assert earlier_event.status_code == 201
    assert later_event.json()["event_id"] != earlier_event.json()["event_id"]
    timeline = client.get(f"/api/v1/investigations/{investigation_id}/timeline", headers=headers)
    assert timeline.status_code == 200
    events = timeline.json()["events"]
    assert [event["event_type"] for event in events] == [
        "INVESTIGATION_CREATED", "DETECTION", "ALERT"
    ]
    assert [event["timestamp"] for event in events] == sorted(event["timestamp"] for event in events)
    assert events[1]["metadata"] == {"assessment_id": "assessment-789"}


def test_case_api_status_lifecycle_and_timeline_changes(tmp_path):
    client, _service, api_key, _ = investigation_client(tmp_path)
    headers = {"Authorization": f"Bearer {api_key}"}
    case = client.post("/api/v1/investigations", json={"title": "Lifecycle test"}, headers=headers).json()
    case_id = case["investigation_id"]

    invalid = client.patch(f"/api/v1/investigations/{case_id}", json={"status": "CLOSED"}, headers=headers)
    assert invalid.status_code == 409
    started = client.patch(f"/api/v1/investigations/{case_id}", json={"status": "IN_PROGRESS"}, headers=headers)
    assert started.status_code == 200
    assert started.json()["status"] == "IN_PROGRESS"
    resolved = client.patch(
        f"/api/v1/investigations/{case_id}",
        json={"status": "RESOLVED", "description": "Evidence reviewed."},
        headers=headers,
    )
    assert resolved.status_code == 200
    assert resolved.json()["description"] == "Evidence reviewed."
    closed = client.post(f"/api/v1/investigations/{case_id}/close", headers=headers)
    assert closed.status_code == 200
    assert closed.json()["status"] == "CLOSED"
    assert client.patch(f"/api/v1/investigations/{case_id}", json={"title": "After close"}, headers=headers).status_code == 409
    assert client.post(
        f"/api/v1/investigations/{case_id}/events",
        json={"event_type": "ANALYST_NOTE", "message": "Too late"},
        headers=headers,
    ).status_code == 409
    timeline = client.get(f"/api/v1/investigations/{case_id}/timeline", headers=headers).json()["events"]
    transitions = [event["metadata"]["status"] for event in timeline if event["event_type"] == "STATUS_CHANGED"]
    assert transitions == ["IN_PROGRESS", "RESOLVED", "CLOSED"]


def test_case_api_auth_not_found_invalid_ids_and_event_validation(tmp_path):
    client, _service, api_key, _ = investigation_client(tmp_path)
    headers = {"Authorization": f"Bearer {api_key}"}
    assert client.post("/api/v1/investigations", json={"title": "No auth"}).status_code == 401
    assert client.post("/api/v1/investigations", json={}, headers=headers).status_code == 422
    assert client.get("/api/v1/investigations/not-a-uuid", headers=headers).status_code == 422
    missing_id = "00000000-0000-4000-8000-000000000001"
    assert client.get(f"/api/v1/investigations/{missing_id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/investigations/{missing_id}/timeline", headers=headers).status_code == 404
    assert client.post(
        f"/api/v1/investigations/{missing_id}/events",
        json={"event_type": "ALERT", "message": "Missing case"},
        headers=headers,
    ).status_code == 404

    case = client.post("/api/v1/investigations", json={"title": "Validation"}, headers=headers).json()
    case_id = case["investigation_id"]
    bad_events = [
        {"event_type": "NOT_SUPPORTED", "message": "Bad type"},
        {"event_type": "ALERT", "message": ""},
        {"event_type": "ALERT", "message": "Bad timestamp", "timestamp": "yesterday"},
        {"event_type": "ALERT", "message": "Secret metadata", "metadata": {"api_key": "do-not-store"}},
        {"event_type": "ALERT", "message": "Bad metadata", "metadata": ["not", "an object"]},
    ]
    for event in bad_events:
        assert client.post(f"/api/v1/investigations/{case_id}/events", json=event, headers=headers).status_code == 422


def test_case_storage_persists_investigation_and_events_after_reload(tmp_path):
    path = tmp_path / "persistent-cases.db"
    original = HubStorage(path)
    case = original.create_investigation(
        title="Persistence test", description="Synthetic case", device_id="DEVICE-PERSIST", sensor_id="SENSOR-PERSIST"
    )
    from rocks.hub.investigation import validate_case_event

    original.add_investigation_event(
        case["investigation_id"],
        validate_case_event({"event_type": "ANALYST_NOTE", "message": "Persisted note."}),
    )
    reloaded = HubStorage(path)
    assert reloaded.get_investigation(case["investigation_id"])["title"] == "Persistence test"
    persisted_events = reloaded.investigation_events(case["investigation_id"])
    assert [event["event_type"] for event in persisted_events] == ["INVESTIGATION_CREATED", "ANALYST_NOTE"]


def test_investigation_cli_uses_configured_local_database(tmp_path, monkeypatch, capsys):
    from rocks.cli import main
    from rocks.config import build_default_config, write_config

    config = build_default_config()
    database_path = tmp_path / "cli-investigations.db"
    config.setdefault("storage", {})["hub_database"] = str(database_path)
    config_path = write_config(config, tmp_path / "config.yaml")
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))

    with pytest.raises(SystemExit) as help_exit:
        main(["investigation", "--help"])
    assert help_exit.value.code == 0
    assert "create" in capsys.readouterr().out
    assert main(["investigation", "create", "--title", "CLI investigation", "--device-id", "DEVICE-CLI"]) == 0
    created = capsys.readouterr().out
    case_id = json.loads(created)["investigation_id"]
    storage = HubStorage(database_path)
    storage.update_investigation(case_id, {"status": "IN_PROGRESS"})
    storage.update_investigation(case_id, {"status": "RESOLVED"})
    assert main(["investigation", "show", case_id]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "RESOLVED"
    assert main(["investigation", "timeline", case_id]) == 0
    assert json.loads(capsys.readouterr().out)[0]["event_type"] == "INVESTIGATION_CREATED"
    assert main(["investigation", "close", case_id]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "CLOSED"
