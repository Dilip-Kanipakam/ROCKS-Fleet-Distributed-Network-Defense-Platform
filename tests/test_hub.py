from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry, telemetry_to_dict
from rocks.hub.app import create_app
from rocks.hub.registry import EdgeRegistry
from rocks.hub.storage import HubStorage


def make_record(sensor_id: str = "EDGE-01"):
    features = TrafficFeatures(0, 60, 2, 120, 120, 0, 1, 1, 1, 1, 1, 2, 0, 0, 0, 2.0, 0.03)
    return behavior_summary_telemetry(features, sensor_id, device_id="DEVICE-01", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))


def client_and_key(tmp_path):
    app = create_app(str(tmp_path / "hub.db"))
    service = app.state.hub_service
    edge, key = service.registry.register("EDGE-01", "Test Edge")
    return TestClient(app), key, service


def test_health_and_edge_endpoints(tmp_path):
    client, key, _service = client_and_key(tmp_path)
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["service"] == "rocks-hub"
    assert client.get("/api/v1/edges").status_code == 401
    edges = client.get("/api/v1/edges", headers={"Authorization": f"Bearer {key}"})
    assert edges.status_code == 200
    assert edges.json()[0]["sensor_id"] == "EDGE-01"
    assert "api_key_hash" not in edges.text


def test_authentication_ingestion_duplicate_and_queries(tmp_path):
    client, key, _service = client_and_key(tmp_path)
    data = telemetry_to_dict(make_record())
    assert client.post("/api/v1/telemetry", json=data).status_code == 401
    assert client.post("/api/v1/telemetry", json=data, headers={"Authorization": "Bearer wrong"}).status_code == 401
    headers = {"Authorization": f"Bearer {key}"}
    first = client.post("/api/v1/telemetry", json=data, headers=headers)
    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    duplicate = client.post("/api/v1/telemetry", json=data, headers=headers)
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert client.get("/api/v1/telemetry").status_code == 401
    listed = client.get("/api/v1/telemetry", params={"sensor_id": "EDGE-01", "device_id": "DEVICE-01"}, headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    fetched = client.get(f"/api/v1/telemetry/{data['record_id']}", headers=headers)
    assert fetched.status_code == 200
    assert client.get("/api/v1/stats", headers=headers).json()["telemetry_records"] == 1
    assert client.get("/api/v1/telemetry", params={"limit": 1001}, headers=headers).status_code == 422


def test_invalid_telemetry_is_rejected(tmp_path):
    client, key, _service = client_and_key(tmp_path)
    response = client.post(
        "/api/v1/telemetry",
        json={"schema_version": "9.0", "sensor_id": "EDGE-01", "event_type": "UNKNOWN"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 422


def test_query_endpoints_require_registered_edge_key(tmp_path):
    client, key, _service = client_and_key(tmp_path)
    record = make_record()
    _edge, _unused_key = _service.registry.register("EDGE-02", "Second Edge")
    _service.storage.insert_telemetry(record)
    endpoints = [
        "/api/v1/telemetry",
        f"/api/v1/telemetry/{record.record_id}",
        "/api/v1/edges",
        "/api/v1/edges/EDGE-01",
        "/api/v1/stats",
    ]
    for endpoint in endpoints:
        assert client.get(endpoint).status_code == 401
        invalid = client.get(endpoint, headers={"Authorization": "Bearer not-a-valid-key"})
        assert invalid.status_code == 401
        assert invalid.json()["detail"] == "Invalid credentials"
        valid = client.get(endpoint, headers={"Authorization": f"Bearer {key}"})
        assert valid.status_code == 200
