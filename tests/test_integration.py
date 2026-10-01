from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from rocks.dashboard.auth import hash_password
from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import TelemetryRecord, behavior_summary_telemetry, telemetry_to_dict
from rocks.hub.app import create_app


def _make_record(sensor_id: str = "EDGE-INT-01", device_id: str = "DEVICE-INT-01") -> TelemetryRecord:
    features = TrafficFeatures(
        window_start=0.0,
        window_end=60.0,
        packet_count=2500,
        total_bytes=1600000,
        bytes_sent=900000,
        bytes_received=700000,
        connection_count=30,
        active_flow_count=12,
        unique_destination_ip_count=40,
        unique_destination_port_count=18,
        unique_source_ip_count=2,
        tcp_packet_count=1500,
        udp_packet_count=500,
        icmp_packet_count=0,
        dns_packet_count=12,
        traffic_rate=240.0,
        packet_rate=41.66,
        device_id=device_id,
        repeated_destination_count=15,
    )
    return behavior_summary_telemetry(
        features,
        sensor_id,
        device_id=device_id,
        timestamp=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
    )


def _make_suspicious_record(sensor_id: str = "EDGE-INT-ALERT", device_id: str = "DEVICE-INT-ALERT") -> TelemetryRecord:
    features = TrafficFeatures(
        window_start=0.0,
        window_end=60.0,
        packet_count=8000,
        total_bytes=8500000,
        bytes_sent=5000000,
        bytes_received=3500000,
        connection_count=120,
        active_flow_count=60,
        unique_destination_ip_count=35,
        unique_destination_port_count=40,
        unique_source_ip_count=3,
        tcp_packet_count=5000,
        udp_packet_count=2000,
        icmp_packet_count=0,
        dns_packet_count=120,
        traffic_rate=550.0,
        packet_rate=133.3,
        device_id=device_id,
        repeated_destination_count=20,
    )
    return behavior_summary_telemetry(
        features,
        sensor_id,
        device_id=device_id,
        timestamp=datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc),
        window_seconds=60.0,
        dns_failure_count=40,
        reconnect_count=12,
        connection_failure_count=8,
    )


def _dashboard_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ROCKS_ADMIN_PASSWORD_HASH", hash_password("correct-password"))
    monkeypatch.setenv("ROCKS_SESSION_SECRET", "test-session-secret")
    return TestClient(create_app(str(tmp_path / "dashboard.db")))


def test_edge_to_hub_telemetry_flow(tmp_path):
    app = create_app(str(tmp_path / "hub.db"))
    client = TestClient(app)
    service = app.state.hub_service
    _, api_key = service.registry.register("EDGE-INT-01", "Integration Edge")

    record = _make_record()
    response = client.post(
        "/api/v1/telemetry",
        json=telemetry_to_dict(record),
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    assert response.json()["duplicate"] is False
    assert response.json()["telemetry_id"] == record.record_id

    stored = service.storage.query_telemetry(sensor_id="EDGE-INT-01", limit=10)
    assert len(stored) == 1
    assert stored[0].record_id == record.record_id

    fetched = client.get(f"/api/v1/telemetry/{record.record_id}", headers={"Authorization": f"Bearer {api_key}"})
    assert fetched.status_code == 200
    assert fetched.json()["record_id"] == record.record_id


def test_detection_to_alert_flow(tmp_path):
    app = create_app(str(tmp_path / "hub.db"))
    service = app.state.hub_service
    sensor_id = "EDGE-INT-ALERT"
    _, api_key = service.registry.register(sensor_id, "Alert Edge")

    record = _make_suspicious_record(sensor_id=sensor_id)
    assessment = service.detection.assess(record)
    alert = service.alerts.create_alert(None, assessment=assessment, record=record)

    assert assessment.triggered is True
    assert alert is not None
    assert alert.sensor_id == sensor_id
    assert alert.telemetry_id == record.record_id
    assert alert.alert_type == "POTENTIAL_ANOMALY"

    assert service.storage.insert_alert(alert) is True
    stored = service.storage.get_alert(alert.alert_id)
    assert stored is not None
    assert stored.alert_id == alert.alert_id
    assert stored.status == "OPEN"

    fetched = TestClient(app).get(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {api_key}"},
        params={"sensor_id": sensor_id, "limit": 5},
    )
    assert fetched.status_code == 200
    assert len(fetched.json()) == 0


def test_dashboard_data_flow_and_safe_error_handling(tmp_path, monkeypatch):
    client = _dashboard_client(tmp_path, monkeypatch)
    service = client.app.state.hub_service
    _, api_key = service.registry.register("EDGE-DASH-01", "Dashboard Edge")

    record = _make_suspicious_record("EDGE-DASH-01", "DEVICE-DASH-01")
    service.ingest(record)
    alert = service.storage.recent_alerts(1)[0]

    login = client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    assert login.status_code == 200
    assert login.history and login.history[0].status_code == 303

    summary = client.get("/api/v1/dashboard/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["edges"]["total"] >= 1
    assert payload["telemetry"]["total"] >= 1
    assert payload["alerts"]["open"] >= 1

    telemetry = client.get("/api/v1/dashboard/telemetry", params={"limit": 10})
    assert telemetry.status_code == 200
    assert telemetry.json()

    alerts = client.get("/api/v1/dashboard/alerts")
    assert alerts.status_code == 200
    assert alerts.json()

    investigation = service.storage.create_investigation(
        title="Dashboard integration case",
        device_id="DEVICE-DASH-01",
        sensor_id="EDGE-DASH-01",
    )
    assert investigation["device_id"] == "DEVICE-DASH-01"

    page = client.get(
        "/dashboard/investigation/DEVICE-DASH-01",
        params={"start": "2025-12-31T00:00:00Z", "end": "2026-01-02T00:00:00Z", "sensor_id": "EDGE-DASH-01"},
    )
    assert page.status_code == 200
    assert "Dashboard integration case" in page.text or "DEVICE-DASH-01" in page.text

    with service.storage._connect() as connection:
        connection.execute(
            "UPDATE telemetry SET payload_json = ? WHERE sensor_id = ?",
            ("{broken-json", "EDGE-DASH-01"),
        )

    dashboard_telemetry = client.get("/api/v1/dashboard/telemetry", params={"limit": 10})
    assert dashboard_telemetry.status_code == 200
    assert "Traceback" not in dashboard_telemetry.text
    assert "password" not in dashboard_telemetry.text.lower()
    assert "api_key" not in dashboard_telemetry.text.lower()

    assert alert["alert_id"]


def test_investigation_flow_through_storage_and_api(tmp_path):
    app = create_app(str(tmp_path / "investigation.db"))
    service = app.state.hub_service
    _, api_key = service.registry.register("EDGE-INV-01", "Investigation Edge")

    case = service.storage.create_investigation(title="Case from integration", device_id="DEVICE-INV-01", sensor_id="EDGE-INV-01")
    case_id = case["investigation_id"]

    note = {
        "event_id": "note-1",
        "timestamp": "2026-01-01T12:00:00Z",
        "event_type": "ANALYST_NOTE",
        "severity": "INFO",
        "message": "Reviewed synthetic activity.",
        "source": "analyst",
        "metadata": {"category": "triage"},
    }
    action = {
        "event_id": "action-1",
        "timestamp": "2026-01-01T12:05:00Z",
        "event_type": "ANALYST_ACTION",
        "severity": "INFO",
        "message": "Escalated for review.",
        "source": "analyst",
        "metadata": {"category": "escalation"},
    }

    stored_note = service.storage.add_investigation_note(case_id, note)
    stored_action = service.storage.add_investigation_action(case_id, action)
    assert stored_note is not None
    assert stored_action is not None
    assert stored_note["note_text"] == "Reviewed synthetic activity."
    assert stored_action["message"] == "Escalated for review."

    telemetry = _make_suspicious_record("EDGE-INV-01", "DEVICE-INV-01")
    service.ingest(telemetry)

    notes = service.storage.investigation_notes(case_id)
    actions = service.storage.investigation_actions(case_id)
    assert len(notes) == 1
    assert len(actions) == 1
    assert notes[0]["author"] == "analyst"
    assert actions[0]["category"] == "escalation"

    client = TestClient(app)
    response = client.get(
        "/api/v1/investigations",
        params={"device_id": "DEVICE-INV-01", "sensor_id": "EDGE-INV-01", "start": "2025-12-31T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["device"]["device_id"] == "DEVICE-INV-01"
    assert body["events"]


def test_demo_and_simulation_workflow_runs_safely():
    from rocks.demo import run_demo_sequence

    result = run_demo_sequence(mode="full", count=2, sensor_id="ROCKS-INT-01")
    assert result["synthetic"] is True
    assert result["no_real_network_activity"] is True
    assert result["telemetry"]
    assert result["records_generated"] == len(result["telemetry"])
    assert result["investigation_id"] is not None
    assert result["alerts"] >= 0

    for item in result["telemetry"]:
        assert "record_id" in item
        assert item["scenario"]
        assert item["sensor_id"] == "ROCKS-INT-01"


def test_failure_and_resilience_cases_are_controlled(tmp_path):
    app = create_app(str(tmp_path / "hub.db"))
    client = TestClient(app)
    service = app.state.hub_service
    _, api_key = service.registry.register("EDGE-FAIL-01", "Failure Edge")

    valid_body = telemetry_to_dict(_make_record("EDGE-FAIL-01", "DEVICE-FAIL-01"))
    bad_auth = client.post(
        "/api/v1/telemetry",
        json=valid_body,
        headers={"Authorization": "Bearer wrong"},
    )
    assert bad_auth.status_code == 401

    missing_fields = client.post(
        "/api/v1/telemetry",
        json={
            "schema_version": "1.0",
            "timestamp": "2026-01-01T12:00:00Z",
            "sensor_id": "EDGE-FAIL-01",
            "event_type": "BEHAVIOR_SUMMARY",
            "payload": {"traffic_rate": 1.0, "packet_count": 1},
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert missing_fields.status_code == 422

    unknown_sensor = client.post(
        "/api/v1/telemetry",
        json=telemetry_to_dict(_make_record("EDGE-UNKNOWN", "DEVICE-UNKNOWN")),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert unknown_sensor.status_code == 401

    with service.storage._connect() as connection:
        connection.execute(
            "INSERT INTO telemetry (id, timestamp, sensor_id, device_id, event_type, schema_version, payload_json, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "broken-telemetry-id",
                "2026-01-01T12:00:00Z",
                "EDGE-FAIL-01",
                "DEVICE-BROKEN",
                "BEHAVIOR_SUMMARY",
                "1.0",
                "{broken-json",
                "2026-01-01T12:00:00Z",
            ),
        )

    dashboard = client.get(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {api_key}"},
        params={"sensor_id": "EDGE-FAIL-01", "limit": 10},
    )
    assert dashboard.status_code == 200
    assert "Traceback" not in dashboard.text
    assert "api_key" not in dashboard.text.lower()
