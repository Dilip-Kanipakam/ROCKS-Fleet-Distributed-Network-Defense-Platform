from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from rocks.dashboard.auth import _b64encode, _encode, create_session, hash_password, verify_session
from rocks.alerts.engine import AlertEngine
from rocks.detection.engine import DetectionEngine
from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry, telemetry_to_dict
from rocks.edge.flow import FlowRecord
from rocks.edge.telemetry import connection_telemetry
from rocks.hub.app import create_app
from rocks.ml.analysis import analyze_behavior_summary


def make_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ROCKS_ADMIN_PASSWORD_HASH", hash_password("correct-password"))
    monkeypatch.setenv("ROCKS_SESSION_SECRET", "test-session-secret")
    return TestClient(create_app(str(tmp_path / "dashboard.db")))


def test_login_protection_and_logout(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    login_page = client.get("/dashboard/login")
    assert login_page.status_code == 200
    assert "Command Center" in login_page.text
    protected = client.get("/dashboard", follow_redirects=False)
    assert protected.status_code == 303
    assert protected.headers["location"] == "/dashboard/login"
    invalid = client.post("/dashboard/login", data={"username": "admin", "password": "wrong"})
    assert invalid.status_code == 401
    valid = client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"}, follow_redirects=False)
    assert valid.status_code == 303
    assert client.get("/dashboard").status_code == 200
    assert client.get("/api/v1/dashboard/summary").status_code == 200
    logout = client.post("/dashboard/logout", follow_redirects=False)
    assert logout.status_code == 303
    assert client.get("/api/v1/dashboard/summary").status_code == 401


def test_malformed_signed_session_claims_are_rejected():
    secret = "test-session-secret"
    encoded = _encode({"username": "admin", "expires": {"unexpected": "type"}})
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    assert verify_session(f"{encoded}.{_b64encode(signature)}", secret) is None
    assert verify_session("not-a-session", secret) is None


def test_session_tokens_are_unique_and_reject_fixation_style_replay():
    secret = "test-session-secret"
    first = create_session("admin", secret, 3600)
    second = create_session("admin", secret, 3600)

    assert first != second
    assert verify_session(first, secret) == "admin"
    assert verify_session(second, secret) == "admin"
    assert verify_session("admin.invalid", secret) is None


def test_empty_dashboard_summary_and_ml_not_ready(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    summary = client.get("/api/v1/dashboard/summary")
    assert summary.status_code == 200
    data = summary.json()
    assert data["edges"] == {"total": 0, "online": 0, "stale": 0, "unknown": 0, "offline": 0}
    assert data["telemetry"]["total"] == 0
    assert data["ml"]["status"] == "NOT_READY"
    assert data["anomalies"]["recent"] == 0
    assert client.get("/dashboard/edges").status_code == 200
    assert client.get("/dashboard/telemetry").status_code == 200
    assert client.get("/dashboard/events").status_code == 200


def test_dashboard_data_filters_limits_and_secrets(tmp_path, monkeypatch):
    app = create_app(str(tmp_path / "dashboard.db"))
    client = TestClient(app)
    monkeypatch.setenv("ROCKS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ROCKS_ADMIN_PASSWORD_HASH", hash_password("correct-password"))
    monkeypatch.setenv("ROCKS_SESSION_SECRET", "test-session-secret")
    # Auth is captured at app creation, so this app intentionally verifies the unconfigured response.
    assert client.get("/api/v1/dashboard/summary").status_code == 401

    client = make_client(tmp_path / "configured", monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    app = client.app
    service = app.state.hub_service
    edge, api_key = service.registry.register("EDGE-01", "Main Sensor")
    features = TrafficFeatures(0, 60, 1, 1000, 500, 500, 1, 1, 1, 1, 1, 1, 0, 0, 0, 16.6, 0.016)
    record = behavior_summary_telemetry(features, "EDGE-01", device_id="DEVICE-01", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    service.storage.insert_telemetry(record)
    analysis = analyze_behavior_summary(record, expected_traffic=500.0, baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    service.storage.insert_analysis(analysis)
    edges = client.get("/api/v1/dashboard/edges")
    assert edges.status_code == 200
    assert edges.json()[0]["sensor_id"] == "EDGE-01"
    assert "api_key_hash" not in edges.text
    telemetry = client.get("/api/v1/dashboard/telemetry", params={"limit": 1, "sensor_id": "EDGE-01"})
    assert telemetry.status_code == 200
    assert len(telemetry.json()) == 1
    assert "payload" not in telemetry.text
    events = client.get("/api/v1/dashboard/events", params={"limit": 1})
    assert events.status_code == 200
    assert events.json()[0]["telemetry_id"] == record.record_id
    assert client.get("/api/v1/dashboard/telemetry", params={"limit": 101}).status_code == 422


def test_ready_ml_summary_state(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    client.app.state.dashboard_service.ml_service = SimpleNamespace(
        model=SimpleNamespace(
            status_dict=lambda: {
                "status": "READY",
                "model_version": "rocks-baseline-v1",
                "training_samples": 25,
                "last_trained": "2026-01-01T00:00:00Z",
            }
        )
    )
    data = client.get("/api/v1/dashboard/summary").json()
    assert data["ml"]["status"] == "READY"
    assert data["ml"]["training_samples"] == 25


def test_alerts_api_returns_investigation_alerts(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    record = behavior_summary_telemetry(
        TrafficFeatures(0, 60, 1, 10000, 5000, 5000, 1, 1, 1, 1, 1, 1, 0, 0, 0, 166.0, 0.1),
        "EDGE-ALERT",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    service.storage.insert_telemetry(record)
    analysis = analyze_behavior_summary(record, expected_traffic=1000, baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    alert = service.alerts.create_alert(analysis)
    assert alert is not None
    service.storage.insert_alert(alert)
    response = client.get("/api/v1/dashboard/alerts")
    assert response.status_code == 200
    assert response.json()[0]["alert_type"] == "POTENTIAL_ANOMALY"


def test_dashboard_events_and_alerts_show_detection_evidence_and_simulation(tmp_path, monkeypatch):
    from rocks.alerts.engine import AlertEngine
    from rocks.detection.config import DetectionConfig
    from rocks.detection.engine import DetectionEngine
    from rocks.simulator.generator import Scenario, generate_records

    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    record = generate_records(Scenario.DEAUTH_RELATED_SIMULATION, count=1)[0]
    service.storage.insert_telemetry(record)
    assessment = DetectionEngine(DetectionConfig()).assess(record)
    service.storage.insert_detection_assessment(assessment)
    alert = AlertEngine().create_alert(None, assessment=assessment, record=record)
    assert alert is not None
    service.storage.insert_alert(alert)

    events_page = client.get("/dashboard/events")
    alerts_page = client.get("/dashboard/alerts")
    alerts_api = client.get("/api/v1/dashboard/alerts")

    assert "SIMULATED" in events_page.text
    assert "DEAUTH_RELATED" in events_page.text
    assert "802.11" not in events_page.text
    assert "SIMULATED" in alerts_page.text
    assert alerts_api.json()[0]["assessment"]["simulation"] is True


def test_dashboard_alert_lifecycle_routes_and_auth(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    service = client.app.state.hub_service
    record = behavior_summary_telemetry(
        TrafficFeatures(0, 60, 1, 10000, 5000, 5000, 1, 1, 1, 1, 1, 1, 0, 0, 0, 166.0, 0.1),
        "EDGE-ALERT-LIFE",
        timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    service.storage.insert_telemetry(record)
    analysis = analyze_behavior_summary(record, expected_traffic=1000, baseline_status="READY", analyzed_at="2026-01-02T00:00:00Z")
    alert = service.alerts.create_alert(analysis)
    assert alert is not None
    service.storage.insert_alert(alert)

    unauth = client.post(f"/api/v1/dashboard/alerts/{alert.alert_id}/acknowledge")
    assert unauth.status_code == 401

    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    ack = client.post(f"/api/v1/dashboard/alerts/{alert.alert_id}/acknowledge")
    assert ack.status_code == 200
    assert ack.json()["status"] == "ACKNOWLEDGED"
    assert service.storage.get_alert(alert.alert_id).status == "ACKNOWLEDGED"

    resolve = client.post(f"/api/v1/dashboard/alerts/{alert.alert_id}/resolve")
    assert resolve.status_code == 200
    assert resolve.json()["status"] == "RESOLVED"
    assert service.storage.get_alert(alert.alert_id).status == "RESOLVED"

    invalid = client.post(f"/api/v1/dashboard/alerts/{alert.alert_id}/acknowledge")
    assert invalid.status_code == 409
    assert service.storage.get_alert(alert.alert_id).status == "RESOLVED"


def test_dashboard_telemetry_handles_connection_unknown_received_bytes(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    _edge, api_key = service.registry.register("EDGE-CONNECTION")
    record = connection_telemetry(
        FlowRecord("192.0.2.1", "198.51.100.1", 1234, 443, "TCP", 10.0, 12.0, 2, 150),
        "EDGE-CONNECTION",
        "DEVICE-1",
        bytes_received=None,
    )
    service.storage.insert_telemetry(record)
    result = client.app.state.dashboard_service.telemetry(limit=10)
    assert result[0]["bytes"] == 150


def test_device_investigation_page_auth_timeline_metadata_detection_ml_and_simulation(tmp_path, monkeypatch):
    from rocks.edge.telemetry import TelemetryRecord
    from rocks.simulator.generator import Scenario, generate_records

    client = make_client(tmp_path, monkeypatch)
    device_id = "DEVICE-DASH-01"
    page = f"/dashboard/investigation/{device_id}"
    assert client.get(page, follow_redirects=False).status_code == 303
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    assert client.get(page + "?start=bad").status_code == 422

    service = client.app.state.hub_service
    connection = connection_telemetry(
        FlowRecord("192.0.2.10", "198.51.100.20", 1234, 443, "TCP", 2, 4, 2, 320),
        "EDGE-DASH", device_id, source_mac="02:00:00:00:00:01", bytes_received=640,
        timestamp=datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc),
    )
    features = TrafficFeatures(0, 60, 3, 10000, 6000, 4000, 2, 2, 1, 1, 1, 1, 0, 0, 0, 250, 0.05, device_id)
    behavior = behavior_summary_telemetry(
        features, "EDGE-DASH", device_id=device_id,
        timestamp=datetime(2026, 9, 30, 12, 1, tzinfo=timezone.utc),
    )
    simulation = generate_records(Scenario.DEAUTH_RELATED_SIMULATION, count=1)[0]
    simulation = TelemetryRecord(
        "EDGE-DASH", device_id, "BEHAVIOR_SUMMARY",
        {**simulation.payload, "simulation": True, "simulation_type": "DEAUTH_RELATED_SIMULATION", "deauth_count": 2},
        timestamp="2026-09-30T12:02:00Z",
    )
    for record in (connection, behavior, simulation):
        service.storage.insert_telemetry(record)

    analysis = analyze_behavior_summary(
        behavior, expected_traffic=1000, baseline_status="READY", analyzed_at="2026-09-30T12:01:30Z"
    )
    service.storage.insert_analysis(analysis)
    assessment = DetectionEngine().assess(behavior, analysis)
    service.storage.insert_detection_assessment(assessment)
    simulation_assessment = DetectionEngine().assess(simulation)
    service.storage.insert_detection_assessment(simulation_assessment)
    alert = service.alerts.create_alert(analysis, assessment=assessment, record=behavior)
    assert alert is not None
    service.storage.insert_alert(alert)
    monkeypatch.setattr(service.email_notifications, "send_alert", lambda *_args: pytest.fail("investigation sent email"))

    response = client.get(
        page,
        params={"start": "2026-09-30T11:59:00Z", "end": "2026-09-30T12:03:00Z", "sensor_id": "EDGE-DASH"},
    )
    assert response.status_code == 200
    html = response.text
    assert "DEVICE INVESTIGATION" in html
    assert "Sensor: EDGE-DASH" in html
    assert "2026-09-30T11:59:00Z" in html
    assert "192.0.2.10" in html
    assert "198.51.100.20" in html
    assert "1234" in html and "443" in html
    assert "Connection Duration Ms" in html
    assert "Bytes" in html
    assert "High traffic activity" in html
    assert "Rule: HIGH_TRAFFIC" in html
    assert "Observed traffic rate was unusually high" in html
    assert "Threshold" in html
    assert "ML signal: Anomaly" in html
    assert "ML baseline analysis" in html
    assert "Deauthentication-related telemetry [SIMULATION ONLY]" in html
    assert "SIMULATION ONLY. This is not an observed Wi-Fi event." in html
    assert "payload" not in html.lower()
    assert html.index("2026-09-30T12:00:00Z") < html.index("2026-09-30T12:01:00Z")


def test_device_investigation_alert_link_and_state_are_read_only(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    device_id = "DEVICE-ALERT-01"
    record = behavior_summary_telemetry(
        TrafficFeatures(0, 60, 1, 10000, 5000, 5000, 1, 1, 1, 1, 1, 1, 0, 0, 0, 250, 0.1, device_id),
        "EDGE-ALERT-01", device_id=device_id,
        timestamp=datetime(2026, 9, 30, 9, tzinfo=timezone.utc),
    )
    service.storage.insert_telemetry(record)
    assessment = DetectionEngine().assess(record)
    service.storage.insert_detection_assessment(assessment)
    alert = AlertEngine().create_alert(None, assessment=assessment, record=record)
    assert alert is not None
    service.storage.insert_alert(alert)
    monkeypatch.setattr(service.email_notifications, "send_alert", lambda *_args: pytest.fail("opening investigation sent email"))

    alerts_page = client.get("/dashboard/alerts")
    assert "Investigate Device" in alerts_page.text
    assert f"/dashboard/investigation/{device_id}" in alerts_page.text
    assert service.storage.get_alert(alert.alert_id).status == "OPEN"
    investigation = client.get(f"/dashboard/investigation/{device_id}?at={record.timestamp}&sensor_id=EDGE-ALERT-01")
    assert investigation.status_code == 200
    assert "OPEN" in investigation.text
    assert service.storage.get_alert(alert.alert_id).status == "OPEN"
    assert service.storage.get_alert(alert.alert_id).notification_attempt_count == 0


def test_dashboard_case_lifecycle_actions_and_closed_case_behavior(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    page = "/dashboard/investigation/DEVICE-CASE-UI"
    assert client.post("/api/v1/dashboard/investigations", json={"title": "Unauthenticated"}).status_code == 401
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    create = client.post(
        "/api/v1/dashboard/investigations",
        json={"title": "Case from dashboard", "description": "Review synthetic evidence.", "device_id": "DEVICE-CASE-UI", "sensor_id": "EDGE-CASE-UI"},
    )
    assert create.status_code == 201
    case_id = create.json()["investigation_id"]
    case_page = client.get(page, params={"case_id": case_id})
    assert case_page.status_code == 200
    assert "Case from dashboard" in case_page.text
    assert "INVESTIGATION_CREATED" in case_page.text
    assert "OPEN" in case_page.text
    assert "Mark In Progress" in case_page.text
    assert "Resolve" not in case_page.text

    invalid = client.patch(f"/api/v1/dashboard/investigations/{case_id}", json={"status": "CLOSED"})
    assert invalid.status_code == 409
    in_progress = client.patch(f"/api/v1/dashboard/investigations/{case_id}", json={"status": "IN_PROGRESS"})
    assert in_progress.status_code == 200
    assert "Mark In Progress" not in client.get(page, params={"case_id": case_id}).text
    resolved = client.patch(f"/api/v1/dashboard/investigations/{case_id}", json={"status": "RESOLVED"})
    assert resolved.status_code == 200
    assert "Close" in client.get(page, params={"case_id": case_id}).text
    closed = client.post(f"/api/v1/dashboard/investigations/{case_id}/close")
    assert closed.status_code == 200
    assert closed.json()["status"] == "CLOSED"
    assert "CLOSED" in client.get(page, params={"case_id": case_id}).text
    assert "Mark In Progress" not in client.get(page, params={"case_id": case_id}).text
    assert client.patch(f"/api/v1/dashboard/investigations/{case_id}", json={"title": "After close"}).status_code == 409
    assert client.post(f"/api/v1/dashboard/investigations/{case_id}/close").status_code == 409


def test_device_investigation_empty_xss_and_storage_failure_states(tmp_path, monkeypatch):
    import sqlite3

    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    empty = client.get("/dashboard/investigation/DEVICE-EMPTY")
    assert empty.status_code == 200
    assert "Device not found" in empty.text

    service = client.app.state.hub_service
    known_record = behavior_summary_telemetry(
        TrafficFeatures(0, 60, 1, 100, 50, 50, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.6, 0.01),
        "EDGE-KNOWN", device_id="DEVICE-KNOWN",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    service.storage.insert_telemetry(known_record)
    known_empty = client.get(
        "/dashboard/investigation/DEVICE-KNOWN",
        params={"start": "2026-09-29T00:00:00Z", "end": "2026-09-30T00:00:00Z"},
    )
    assert known_empty.status_code == 200
    assert "No evidence or case events" in known_empty.text

    case = service.storage.create_investigation(title="<script>alert(1)</script>", device_id="DEVICE-XSS")
    response = client.get(f"/dashboard/investigation/DEVICE-XSS?case_id={case['investigation_id']}")
    assert response.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>alert(1)</script>" not in response.text

    monkeypatch.setattr(service.storage, "investigation_timeline", lambda **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("private database detail")))
    unavailable = client.get("/dashboard/investigation/DEVICE-EMPTY")
    assert unavailable.status_code == 503
    assert "temporarily unavailable" in unavailable.text
    assert "private database detail" not in unavailable.text


def test_dashboard_analyst_notes_actions_auth_timeline_and_closed_case(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    case_id = "00000000-0000-4000-8000-000000000007"
    note_url = f"/api/v1/dashboard/investigations/{case_id}/notes"
    action_url = f"/api/v1/dashboard/investigations/{case_id}/actions"
    assert client.post(note_url, json={"note_text": "No session"}).status_code == 401

    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    storage = client.app.state.hub_service.storage
    case = storage.create_investigation(title="Analyst UI case", device_id="DEVICE-ANALYST-UI")
    case_id = case["investigation_id"]
    note_url = f"/api/v1/dashboard/investigations/{case_id}/notes"
    action_url = f"/api/v1/dashboard/investigations/{case_id}/actions"
    note = client.post(note_url, json={"note_text": "Reviewed counters; no payload retained."})
    action = client.post(action_url, json={"category": "TRAFFIC_REVIEWED"})
    assert note.status_code == 201
    assert note.json()["author"] == "admin"
    assert action.status_code == 201
    assert action.json()["author"] == "admin"

    page = client.get(f"/dashboard/investigation/DEVICE-ANALYST-UI?case_id={case_id}")
    assert page.status_code == 200
    assert "Analyst notes" in page.text
    assert "Reviewed counters; no payload retained." in page.text
    assert "admin" in page.text
    assert "Record investigation action" in page.text
    assert "TRAFFIC_REVIEWED" in page.text
    assert "ANALYST_NOTE" in page.text
    assert "ANALYST_ACTION" in page.text

    storage.update_investigation(case_id, {"status": "IN_PROGRESS"})
    storage.update_investigation(case_id, {"status": "RESOLVED"})
    assert client.post(f"/api/v1/dashboard/investigations/{case_id}/close").status_code == 200
    closed_page = client.get(f"/dashboard/investigation/DEVICE-ANALYST-UI?case_id={case_id}")
    assert "This case is closed. Notes and actions are read-only." in closed_page.text
    assert '<form id="analyst-note-form"' not in closed_page.text
    assert client.post(note_url, json={"note_text": "Closed write rejected."}).status_code == 409
    assert len(storage.investigation_notes(case_id)) == 1


def test_fleet_summary_edge_freshness_alerts_and_investigation_entry(tmp_path, monkeypatch):
    from datetime import timedelta

    from rocks.alerts.engine import Alert
    from rocks.edge.telemetry import TelemetryRecord, utc_timestamp

    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    storage = service.storage
    timestamp = utc_timestamp(datetime.now(timezone.utc))
    event_timestamp = utc_timestamp(datetime.now(timezone.utc) - timedelta(days=1))
    for sensor_id in ("EDGE-ONLINE", "EDGE-STALE", "EDGE-UNKNOWN"):
        service.registry.register(sensor_id)
    storage.touch_edge("EDGE-ONLINE")
    old_seen = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with storage._connect() as connection:
        connection.execute("UPDATE edges SET last_seen = ? WHERE sensor_id = ?", (old_seen, "EDGE-STALE"))
    storage.insert_telemetry(TelemetryRecord("EDGE-ONLINE", "DEVICE-OVERVIEW", "CONNECTION", {"source": {"ip": "192.0.2.7"}}, timestamp=event_timestamp))

    alert = Alert(
        alert_id="overview-alert-1", timestamp=timestamp, telemetry_id="overview-telemetry-1",
        sensor_id="EDGE-ONLINE", device_id="DEVICE-OVERVIEW", alert_type="POTENTIAL_ANOMALY",
        severity="CRITICAL", anomaly_score=None, retention_score=None,
        message="High-priority behavior requires review.",
    )
    storage.insert_alert(alert)
    with storage._connect() as connection:
        connection.execute("UPDATE alerts SET notification_error = ? WHERE alert_id = ?", ("SMTP_PASSWORD=private-test-value", alert.alert_id))
    case = storage.create_investigation(title="Overview case", device_id="DEVICE-OVERVIEW", sensor_id="EDGE-ONLINE")

    summary_response = client.get("/api/v1/dashboard/summary")
    assert summary_response.status_code == 200
    data = summary_response.json()
    assert data["edges"] == {"total": 3, "online": 1, "stale": 1, "unknown": 1, "offline": 2}
    assert data["telemetry"]["recent"] == 1
    assert data["alerts"]["open"] == 1
    assert data["alerts"]["high_critical"] == 1
    assert data["alerts"]["recent"] == 1
    assert data["investigations"]["open"] == 1
    assert data["alerts"]["recent_items"][0]["rule_name"] is None
    assert "notification_error" not in summary_response.text
    assert "SMTP_PASSWORD" not in summary_response.text
    assert "private-test-value" not in summary_response.text

    edges = client.get("/api/v1/dashboard/edges").json()
    by_sensor = {item["sensor_id"]: item for item in edges}
    assert by_sensor["EDGE-ONLINE"]["status"] == "ONLINE"
    assert by_sensor["EDGE-ONLINE"]["last_telemetry_timestamp"] == event_timestamp
    assert by_sensor["EDGE-ONLINE"]["telemetry_count"] == 1
    assert by_sensor["EDGE-STALE"]["status"] == "STALE"
    assert by_sensor["EDGE-UNKNOWN"]["status"] == "UNKNOWN"

    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "Investigate Device" in page.text
    assert f"/dashboard/investigation/DEVICE-OVERVIEW" in page.text
    assert alert.timestamp in page.text
    assert case["investigation_id"] not in page.text
    assert "private-test-value" not in page.text


def test_dashboard_health_summary_empty_states_and_page_auth(tmp_path, monkeypatch):
    from rocks.health import HealthCheck, HealthStatus

    client = make_client(tmp_path, monkeypatch)
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    assert client.get("/api/v1/dashboard/summary").status_code == 401
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})

    report = SimpleNamespace(
        overall=HealthStatus.DEGRADED,
        checks=(
            HealthCheck("hub_database", HealthStatus.OK, "Hub SQLite database is readable."),
            HealthCheck("telemetry", HealthStatus.WARNING, "Telemetry is stale."),
            HealthCheck("hub_service", HealthStatus.UNKNOWN, "Service state is unavailable."),
        ),
    )
    monkeypatch.setattr("rocks.dashboard.service.HealthChecker", lambda: SimpleNamespace(run=lambda: report))
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "DEGRADED" in page.text
    assert "Hub Database" in page.text
    assert "Telemetry is stale." in page.text
    assert "Service state is unavailable." in page.text
    assert "No Edge sensors registered." in page.text
    assert "No alerts were created in the last 24 hours." in page.text
    assert "No telemetry available." in page.text
    assert "password_hash" not in page.text
    assert "session_secret" not in page.text


def test_dashboard_alert_reads_tolerate_corrupt_assessment_and_redact_internal_error(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    record = behavior_summary_telemetry(
        TrafficFeatures(0, 60, 1, 1000, 500, 500, 1, 1, 1, 1, 1, 1, 0, 0, 0, 250, 0.02),
        "EDGE-CORRUPT",
        device_id="DEVICE-CORRUPT",
        timestamp=datetime.now(timezone.utc),
    )
    service.storage.insert_telemetry(record)
    alert = AlertEngine().create_alert(None, assessment=DetectionEngine().assess(record), record=record)
    assert alert is not None
    service.storage.insert_alert(alert)
    with service.storage._connect() as connection:
        connection.execute(
            "UPDATE alerts SET assessment_json = ?, notification_error = ? WHERE alert_id = ?",
            ("{invalid-json", "SMTP_PASSWORD=do-not-expose", alert.alert_id),
        )

    api = client.get("/api/v1/dashboard/alerts")
    page = client.get("/dashboard/alerts")
    assert api.status_code == 200
    assert page.status_code == 200
    assert "do-not-expose" not in api.text + page.text
    assert "SMTP_PASSWORD" not in api.text + page.text
    assert "password" not in api.text.lower() + page.text.lower()


def test_corrupt_stored_telemetry_is_skipped_safely(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    _edge, api_key = service.registry.register("EDGE-CORRUPT-TELEMETRY")
    record = behavior_summary_telemetry(
        TrafficFeatures(0, 60, 1, 100, 50, 50, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.6, 0.01),
        "EDGE-CORRUPT-TELEMETRY",
        device_id="DEVICE-CORRUPT-TELEMETRY",
        timestamp=datetime.now(timezone.utc),
    )
    service.storage.insert_telemetry(record)
    with service.storage._connect() as connection:
        connection.execute("UPDATE telemetry SET payload_json = ? WHERE id = ?", ("{broken-json", record.record_id))

    dashboard_list = client.get("/api/v1/dashboard/telemetry")
    dashboard_page = client.get("/dashboard/telemetry")
    hub_item = client.get(
        f"/api/v1/telemetry/{record.record_id}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert dashboard_list.status_code == 200
    assert dashboard_list.json() == []
    assert dashboard_page.status_code == 200
    assert "Traceback" not in dashboard_page.text
    assert hub_item.status_code == 404


def test_database_error_response_and_logs_are_sanitized(tmp_path, monkeypatch):
    import io
    import logging
    import sqlite3

    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    service = client.app.state.hub_service
    captured = io.StringIO()
    handler = logging.StreamHandler(captured)
    service._logger.addHandler(handler)
    monkeypatch.setattr(
        service.storage,
        "dashboard_edges",
        lambda **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("password=do-not-log")),
    )
    try:
        response = client.get("/api/v1/dashboard/edges")
    finally:
        service._logger.removeHandler(handler)
    assert response.status_code == 503
    assert response.json() == {"detail": "Storage is temporarily unavailable"}
    assert "do-not-log" not in response.text
    assert "do-not-log" not in captured.getvalue()
    assert "OperationalError" in captured.getvalue()
