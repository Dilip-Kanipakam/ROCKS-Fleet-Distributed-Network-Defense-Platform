from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from rocks.dashboard.auth import hash_password
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


def test_empty_dashboard_summary_and_ml_not_ready(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    client.post("/dashboard/login", data={"username": "admin", "password": "correct-password"})
    summary = client.get("/api/v1/dashboard/summary")
    assert summary.status_code == 200
    data = summary.json()
    assert data["edges"] == {"total": 0, "online": 0, "offline": 0}
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
