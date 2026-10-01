from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from rocks import __version__
from rocks.cli import main
from rocks.dashboard.auth import hash_password
from rocks.edge.features import TrafficFeatures
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import PacketMetadata
from rocks.edge.telemetry import behavior_summary_telemetry, telemetry_to_dict
from rocks.hub.app import create_app
from rocks.ml.service import MAX_TRAINING_RECORDS, MLService
from rocks.simulator.generator import generate_records


def _record(sensor_id: str, device_id: str) -> object:
    features = TrafficFeatures(0, 60, 1, 120, 120, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 2.0, 0.02, device_id)
    return behavior_summary_telemetry(features, sensor_id, device_id=device_id, timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_version_and_cli_semantics(capsys):
    assert __version__ == "1.1.0.dev0"
    assert main(["version"]) == 0
    assert "1.1.0.dev0" in capsys.readouterr().out
    assert main(["test"]) == 0
    output = capsys.readouterr().out
    assert "does not run pytest" in output
    assert ".venv/bin/python -m pytest -q" in output
    assert main(["logs"]) == 0
    assert "journalctl" in capsys.readouterr().out


def test_edge_keys_are_sensor_scoped_and_admin_key_is_fleet_scoped(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_API_KEY", "fleet-admin-key")
    app = create_app(str(tmp_path / "hub.db"))
    service = app.state.hub_service
    _, key_a = service.registry.register("EDGE-A", "A")
    _, key_b = service.registry.register("EDGE-B", "B")
    client = TestClient(app)
    for sensor_id, key in (("EDGE-A", key_a), ("EDGE-B", key_b)):
        record = _record(sensor_id, f"DEVICE-{sensor_id[-1]}")
        response = client.post("/api/v1/telemetry", json=telemetry_to_dict(record), headers={"Authorization": f"Bearer {key}"})
        assert response.status_code == 200

    own = client.get("/api/v1/telemetry", params={"sensor_id": "EDGE-A"}, headers={"Authorization": f"Bearer {key_a}"})
    cross = client.get("/api/v1/telemetry", params={"sensor_id": "EDGE-B"}, headers={"Authorization": f"Bearer {key_a}"})
    unscoped = client.get("/api/v1/telemetry", headers={"Authorization": f"Bearer {key_a}"})
    admin = client.get("/api/v1/telemetry", headers={"Authorization": "Bearer fleet-admin-key"})
    assert own.status_code == 200 and len(own.json()) == 1
    assert cross.status_code == 403
    assert unscoped.status_code == 200 and len(unscoped.json()) == 1
    assert admin.status_code == 200 and len(admin.json()) == 2

    edge_b_record_id = client.get("/api/v1/telemetry", params={"sensor_id": "EDGE-B"}, headers={"Authorization": f"Bearer {key_b}"}).json()[0]["record_id"]
    assert client.get(f"/api/v1/telemetry/{edge_b_record_id}", headers={"Authorization": f"Bearer {key_a}"}).status_code == 403
    assert client.get("/api/v1/stats", headers={"Authorization": f"Bearer {key_a}"}).status_code == 403

    investigation = client.get("/api/v1/investigations", params={"device_id": "DEVICE-A", "sensor_id": "EDGE-A"}, headers={"Authorization": f"Bearer {key_a}"})
    cross_investigation = client.get("/api/v1/investigations", params={"device_id": "DEVICE-B", "sensor_id": "EDGE-B"}, headers={"Authorization": f"Bearer {key_a}"})
    fleet_investigation = client.get("/api/v1/investigations", params={"device_id": "DEVICE-A"}, headers={"Authorization": "Bearer fleet-admin-key"})
    assert investigation.status_code == 200
    assert cross_investigation.status_code == 403
    assert fleet_investigation.status_code == 200

    case_without_admin = client.post("/api/v1/investigations", json={"title": "Edge case"}, headers={"Authorization": f"Bearer {key_a}"})
    case_with_admin = client.post("/api/v1/investigations", json={"title": "Admin case"}, headers={"Authorization": "Bearer fleet-admin-key"})
    assert case_without_admin.status_code == 401
    assert case_with_admin.status_code == 201


def test_flow_tracker_capacity_evicts_oldest_and_rejects_invalid_limits():
    for invalid in (0, -1, 10.5, "100", True, False, None):
        with pytest.raises(ValueError):
            FlowTracker(max_active_flows=invalid)
    tracker = FlowTracker(expiration_seconds=300, max_active_flows=2)
    packets = [
        PacketMetadata(1, 10, "192.0.2.1", "198.51.100.1", "TCP", 1000, 443),
        PacketMetadata(2, 10, "192.0.2.2", "198.51.100.2", "TCP", 1001, 443),
        PacketMetadata(3, 10, "192.0.2.3", "198.51.100.3", "TCP", 1002, 443),
    ]
    for packet in packets:
        tracker.update(packet)
    assert tracker.active_flow_count == 2
    assert {flow.source_ip for flow in tracker.flows} == {"192.0.2.2", "192.0.2.3"}
    assert len(tracker.expire(304)) == 2


def test_malformed_dashboard_login_is_controlled(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ROCKS_ADMIN_PASSWORD_HASH", hash_password("password"))
    monkeypatch.setenv("ROCKS_SESSION_SECRET", "session-secret")
    client = TestClient(create_app(str(tmp_path / "hub.db")))
    assert client.post("/dashboard/login", content=b"\xff\xfe").status_code == 422
    assert client.post("/dashboard/login", data={}).status_code == 401
    assert client.post("/dashboard/login", data={"username": "admin"}).status_code == 401
    assert client.post("/dashboard/login", data={"username": "admin", "password": "password"}, follow_redirects=False).status_code == 303


def test_dashboard_mutations_reject_cross_origin_but_allow_same_origin(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ROCKS_ADMIN_PASSWORD_HASH", hash_password("password"))
    monkeypatch.setenv("ROCKS_SESSION_SECRET", "session-secret")
    client = TestClient(create_app(str(tmp_path / "hub.db")))
    assert client.post("/api/v1/dashboard/investigations", json={"title": "No auth"}).status_code == 401
    assert client.post("/dashboard/login", data={"username": "admin", "password": "password"}, headers={"Origin": "https://evil.example"}).status_code == 403
    client.post("/dashboard/login", data={"username": "admin", "password": "password"})
    bad = client.post("/api/v1/dashboard/investigations", json={"title": "Bad origin"}, headers={"Origin": "https://evil.example"})
    bad_referer = client.post("/api/v1/dashboard/investigations", json={"title": "Bad referer"}, headers={"Referer": "https://evil.example/form"})
    good = client.post("/api/v1/dashboard/investigations", json={"title": "Same origin"}, headers={"Origin": "http://testserver"})
    good_referer = client.post("/api/v1/dashboard/investigations", json={"title": "Same referer"}, headers={"Referer": "http://testserver/form"})
    missing_origin = client.post("/api/v1/dashboard/investigations", json={"title": "No origin"})
    read_only = client.get("/api/v1/dashboard/summary", headers={"Origin": "https://evil.example"})
    assert bad.status_code == 403
    assert bad_referer.status_code == 403
    assert good.status_code == 201
    assert good_referer.status_code == 201
    assert missing_origin.status_code == 201
    assert read_only.status_code == 200


def test_simulator_cli_labels_all_records_as_synthetic(capsys):
    assert main(["simulate", "high_traffic"]) == 0
    normal_output = capsys.readouterr().out
    assert "Synthetic data: yes" in normal_output
    assert "Explicit simulation marker: no" in normal_output
    assert main(["simulate", "deauth_related_simulation"]) == 0
    simulated_output = capsys.readouterr().out
    assert "Synthetic data: yes" in simulated_output
    assert "Explicit simulation marker: yes" in simulated_output


def test_ml_training_uses_storage_bound(monkeypatch, tmp_path):
    class Storage:
        def __init__(self):
            self.limit = None

        def query_telemetry(self, **kwargs):
            self.limit = kwargs["limit"]
            return []

    storage = Storage()
    service = MLService(storage, tmp_path / "model.joblib")
    monkeypatch.setattr(service.model, "train", lambda records: len(records))
    assert service.train() == 0
    assert storage.limit == MAX_TRAINING_RECORDS == 1000
