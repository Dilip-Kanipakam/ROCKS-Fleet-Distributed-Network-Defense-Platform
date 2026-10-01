from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from rocks.edge.features import TrafficFeatures
from rocks.edge.flow import FlowRecord
from rocks.edge.telemetry import (
    behavior_summary_telemetry,
    connection_telemetry,
    dns_telemetry,
    reconnect_telemetry,
    telemetry_to_dict,
)
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
    assert client.get("/api/v1/stats", headers=headers).status_code == 403
    assert client.get("/api/v1/telemetry", params={"limit": 1001}, headers=headers).status_code == 422


def test_invalid_telemetry_is_rejected(tmp_path):
    client, key, _service = client_and_key(tmp_path)
    response = client.post(
        "/api/v1/telemetry",
        json={"schema_version": "9.0", "sensor_id": "EDGE-01", "event_type": "UNKNOWN"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 422


def test_telemetry_ingest_rejects_malformed_unbounded_and_sensitive_input(tmp_path):
    client, key, _service = client_and_key(tmp_path)
    headers = {"Authorization": f"Bearer {key}"}
    valid = telemetry_to_dict(make_record())

    bad_inputs = []
    bad_timestamp = dict(valid, timestamp="not-a-timestamp")
    bad_inputs.append(bad_timestamp)
    bad_sensor = dict(valid, sensor_id="bad/sensor")
    bad_inputs.append(bad_sensor)
    unexpected = dict(valid, internal_token="must-not-be-accepted")
    bad_inputs.append(unexpected)
    sensitive_payload = dict(valid, payload={**valid["payload"], "packet_payload": "raw bytes"})
    bad_inputs.append(sensitive_payload)
    nonfinite_payload = dict(valid, payload={**valid["payload"], "custom_metric": float("nan")})
    bad_inputs.append(nonfinite_payload)
    oversized_payload = dict(valid, payload={**valid["payload"], "description": "x" * (33 * 1024)})
    bad_inputs.append(oversized_payload)
    nested: object = "value"
    for _ in range(34):
        nested = {"child": nested}
    nested_payload = dict(valid, payload={**valid["payload"], "nested": nested})
    bad_inputs.append(nested_payload)

    for body in bad_inputs:
        if body is nonfinite_payload:
            response = client.post(
                "/api/v1/telemetry",
                content=json.dumps(body, allow_nan=True),
                headers={**headers, "Content-Type": "application/json"},
            )
            assert response.status_code == 422
            continue
        response = client.post("/api/v1/telemetry", json=body, headers=headers)
        assert response.status_code == 422
    oversized_request = client.post(
        "/api/v1/telemetry",
        content=b"x" * (129 * 1024),
        headers={**headers, "Content-Type": "application/json"},
    )
    assert oversized_request.status_code == 413
    malformed = client.post(
        "/api/v1/telemetry",
        content=b"{",
        headers={**headers, "Content-Type": "application/json"},
    )
    assert malformed.status_code == 422


def test_telemetry_ingest_rejects_type_coercion_and_invalid_paths(tmp_path):
    client, key, _service = client_and_key(tmp_path)
    headers = {"Authorization": f"Bearer {key}"}
    valid = telemetry_to_dict(make_record())

    for field, value in (("sensor_id", 42), ("device_id", 42), ("timestamp", 42), ("payload", [])):
        response = client.post(
            "/api/v1/telemetry",
            json={**valid, field: value},
            headers=headers,
        )
        assert response.status_code == 422

    assert client.get("/api/v1/telemetry/not%20an%20id", headers=headers).status_code == 422
    assert client.get("/api/v1/edges/bad!sensor", headers=headers).status_code == 422


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
        params = {"sensor_id": "EDGE-01"} if endpoint == "/api/v1/telemetry" else {}
        valid = client.get(endpoint, params=params, headers={"Authorization": f"Bearer {key}"})
        assert valid.status_code == (403 if endpoint == "/api/v1/stats" else 200)


def test_hub_accepts_existing_edge_event_types(tmp_path):
    client, key, service = client_and_key(tmp_path)
    headers = {"Authorization": f"Bearer {key}"}
    flow = FlowRecord("192.0.2.1", "198.51.100.1", 1234, 443, "TCP", 10.0, 12.0, 2, 150)
    records = [
        connection_telemetry(flow, "EDGE-01", "DEVICE-01"),
        dns_telemetry(
            "EDGE-01",
            source_ip="192.0.2.1",
            source_port=53000,
            destination_ip="198.51.100.53",
            destination_port=53,
            request_count=2,
            device_id="DEVICE-01",
        ),
        reconnect_telemetry("EDGE-01", reconnect_count=1, connection_failure_count=1, device_id="DEVICE-01"),
        make_record(),
    ]
    for record in records:
        response = client.post("/api/v1/telemetry", json=telemetry_to_dict(record), headers=headers)
        assert response.status_code == 200
    assert service.storage.count() == 4
    for event_type in ("CONNECTION", "DNS", "RECONNECT", "BEHAVIOR_SUMMARY"):
        assert service.storage.query_telemetry(event_type=event_type)[0].event_type == event_type
