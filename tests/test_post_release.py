from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import socket

import pytest
from fastapi.testclient import TestClient
import yaml

from rocks import __version__
from rocks.cli import main
from rocks.dashboard.auth import hash_password
from rocks.edge.features import TrafficFeatures
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import PacketMetadata
from rocks.edge.telemetry import behavior_summary_telemetry, telemetry_to_dict
from rocks.hub.app import create_app
from rocks.health import HealthChecker, HealthStatus
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
    own_context = client.get("/api/v1/telemetry/context", params={"telemetry_id": edge_b_record_id}, headers={"Authorization": f"Bearer {key_b}"})
    cross_context = client.get("/api/v1/telemetry/context", params={"telemetry_id": edge_b_record_id}, headers={"Authorization": f"Bearer {key_a}"})
    admin_context = client.get("/api/v1/telemetry/context", params={"telemetry_id": edge_b_record_id}, headers={"Authorization": "Bearer fleet-admin-key"})
    assert own_context.status_code == 200
    assert cross_context.status_code == 403
    assert admin_context.status_code == 200
    assert client.get("/api/v1/telemetry/context", params={"telemetry_id": edge_b_record_id}, headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert client.get("/api/v1/telemetry/context", params={"telemetry_id": edge_b_record_id}).status_code == 401

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


def test_three_edges_share_one_hub_and_remain_sensor_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_API_KEY", "fleet-admin-key")
    app = create_app(str(tmp_path / "hub.db"))
    service = app.state.hub_service
    keys = {}
    for sensor_id in ("EDGE-01", "EDGE-02", "EDGE-03"):
        _, key = service.registry.register(sensor_id, sensor_id)
        keys[sensor_id] = key

    client = TestClient(app)
    for sensor_id in ("EDGE-01", "EDGE-02", "EDGE-03"):
        response = client.post(
            "/api/v1/telemetry",
            json=telemetry_to_dict(_record(sensor_id, f"DEVICE-{sensor_id[-1]}")),
            headers={"Authorization": f"Bearer {keys[sensor_id]}"},
        )
        assert response.status_code == 200

    for sensor_id in ("EDGE-01", "EDGE-02", "EDGE-03"):
        response = client.get(
            "/api/v1/telemetry",
            params={"sensor_id": sensor_id},
            headers={"Authorization": f"Bearer {keys[sensor_id]}"},
        )
        assert response.status_code == 200
        payload = response.json()
        assert len(payload) == 1
        assert payload[0]["sensor_id"] == sensor_id

    cross = client.get(
        "/api/v1/telemetry",
        params={"sensor_id": "EDGE-02"},
        headers={"Authorization": f"Bearer {keys['EDGE-01']}"},
    )
    assert cross.status_code == 403

    admin = client.get("/api/v1/telemetry", headers={"Authorization": "Bearer fleet-admin-key"})
    assert admin.status_code == 200
    admin_payload = admin.json()
    assert len(admin_payload) == 3
    assert {row["sensor_id"] for row in admin_payload} == {"EDGE-01", "EDGE-02", "EDGE-03"}


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


def test_simulator_cli_uses_configured_edge_identity_and_key(capsys, monkeypatch):
    captured = {}

    class StubAgent:
        def __init__(self, config):
            captured["config"] = config

        def run_dry_run(self, records):
            captured["records"] = records
            return type("SendResult", (), {"sent": len(records), "failed": 0})()

    monkeypatch.setattr(
        "rocks.cli.get_edge_agent_config",
        lambda: {
            "sensor_id": "ROCKS-EDGE-01",
            "hub_url": "http://hub.local",
            "api_key": "edge-01-key",
        },
    )
    monkeypatch.setattr("rocks.cli.EdgeAgent", StubAgent)

    assert main(["simulate", "--scenario", "high_traffic"]) == 0

    output = capsys.readouterr().out
    assert "Sensor ID: ROCKS-EDGE-01" in output
    assert "Synthetic data: yes" in output
    assert "Explicit simulation marker: yes" in output
    assert captured["config"].sensor_id == "ROCKS-EDGE-01"
    assert captured["config"].api_key == "edge-01-key"
    assert all(record.sensor_id == "ROCKS-EDGE-01" for record in captured["records"])
    assert all(record.payload["simulation"] is True for record in captured["records"])


def test_simulator_cli_rejects_sensor_id_without_matching_credentials(capsys, monkeypatch):
    monkeypatch.setattr(
        "rocks.cli.get_edge_agent_config",
        lambda: {
            "sensor_id": "ROCKS-EDGE-01",
            "hub_url": "http://hub.local",
            "api_key": "edge-01-key",
        },
    )
    monkeypatch.setattr(
        "rocks.cli.EdgeAgent",
        lambda *_args, **_kwargs: pytest.fail("unauthorized sensor must not be delivered"),
    )

    assert main(["simulate", "--scenario", "high_traffic", "--sensor-id", "ROCKS-OTHER-01"]) == 2

    assert "--sensor-id must match the configured Edge sensor" in capsys.readouterr().err


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


def test_setup_and_health_reject_invalid_max_active_flows(tmp_path):
    interface = socket.if_nameindex()[0][1]
    config = yaml.safe_load(Path("config/config.example.yaml").read_text())
    config["deployment"]["mode"] = "edge"
    config["edge"].update({"sensor_id": "EDGE-CONFIG", "interface": interface, "hub_url": "http://127.0.0.1:8000"})
    config["hub"]["api_key"] = "edge-key"
    config_path = tmp_path / "config.yaml"

    for invalid in (0, -1, 10.5, "100", True, False, None):
        config["edge"]["max_active_flows"] = invalid
        config_path.write_text(yaml.safe_dump(config))
        config_path.chmod(0o600)
        assert main(["setup", "--config-path", str(config_path), "--check"]) == 2
        report = HealthChecker(config_path=config_path).run()
        assert report.get("configuration").status == HealthStatus.ERROR

    for valid in (1, 2, 10000):
        config["edge"]["max_active_flows"] = valid
        config_path.write_text(yaml.safe_dump(config))
        config_path.chmod(0o600)
        assert main(["setup", "--config-path", str(config_path), "--check"]) == 0
        report = HealthChecker(config_path=config_path).run()
        assert report.get("configuration").status == HealthStatus.OK


def test_negative_numeric_telemetry_values_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_API_KEY", "fleet-admin-key")
    app = create_app(str(tmp_path / "hub.db"))
    service = app.state.hub_service
    _, key = service.registry.register("EDGE-NEG", "NEG")
    client = TestClient(app)
    record = _record("EDGE-NEG", "DEVICE-NEG")
    bad = telemetry_to_dict(record)
    bad["payload"]["packet_count"] = -1
    response = client.post("/api/v1/telemetry", json=bad, headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 422
    assert "negative" in response.json()["detail"].lower()


def test_buffer_enforces_hard_capacity(tmp_path):
    from rocks.edge.buffer import TelemetryBuffer

    buffer = TelemetryBuffer(tmp_path / "buffer.db", buffer_limit=2)
    first = _record("EDGE-A", "DEVICE-A")
    second = _record("EDGE-B", "DEVICE-B")
    third = _record("EDGE-C", "DEVICE-C")
    buffer.add(first)
    buffer.add(second)
    buffer.add(third)
    assert buffer.size() == 2
    remaining = {record.record_id for record in buffer.peek(limit=2)}
    assert remaining == {second.record_id, third.record_id}
    assert first.record_id not in remaining


def test_corrupt_ml_model_loads_as_not_ready(tmp_path):
    model_path = tmp_path / "corrupt.joblib"
    model_path.write_bytes(b"not a valid joblib payload")
    model = MLService.__dict__["__init__"] if False else None
    from rocks.ml.baseline import BaselineModel

    loaded = BaselineModel.load(model_path)
    assert loaded.status.value == "NOT_READY"
    assert loaded.model is None


def test_context_endpoint_rejects_bad_or_missing_telemetry_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_API_KEY", "fleet-admin-key")
    app = create_app(str(tmp_path / "hub.db"))
    service = app.state.hub_service
    _, key = service.registry.register("EDGE-CTX", "CTX")
    client = TestClient(app)
    record = _record("EDGE-CTX", "DEVICE-CTX")
    response = client.post("/api/v1/telemetry", json=telemetry_to_dict(record), headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 200

    missing_response = client.get("/api/v1/telemetry/context", params={"telemetry_id": "missing-telemetry-id"}, headers={"Authorization": f"Bearer {key}"})
    invalid_response = client.get("/api/v1/telemetry/context", params={"telemetry_id": "bad;id"}, headers={"Authorization": f"Bearer {key}"})
    assert missing_response.status_code == 404
    assert invalid_response.status_code == 422
