from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from rocks.dashboard.auth import hash_password
from rocks.edge.features import TrafficFeatures
from rocks.edge.flow import FlowRecord
from rocks.edge.telemetry import behavior_summary_telemetry, connection_telemetry, dns_telemetry, telemetry_to_dict
from rocks.hub.app import create_app
from rocks.hub.storage import HubStorage
from rocks.ml.analysis import analyze_behavior_summary


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
