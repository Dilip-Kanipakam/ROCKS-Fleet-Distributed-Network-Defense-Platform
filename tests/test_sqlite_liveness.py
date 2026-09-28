from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from rocks.dashboard.auth import hash_password
from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.features import TrafficFeatures
from rocks.edge.storage import TelemetryStorage
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.hub.storage import HubStorage, edge_liveness_status
from rocks.hub.app import create_app
from rocks.sqlite import SQLITE_BUSY_TIMEOUT_MS, connect_sqlite


def sample_record(sensor_id: str = "EDGE-TEST"):
    features = TrafficFeatures(0, 60, 1, 100, 50, 50, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.66, 0.016)
    return behavior_summary_telemetry(features, sensor_id, device_id="DEVICE-TEST")


def test_edge_sqlite_stores_use_wal_busy_timeout_and_keep_data(tmp_path):
    telemetry_path = tmp_path / "edge.db"
    telemetry_storage = TelemetryStorage(telemetry_path)
    telemetry_storage.initialize()
    assert telemetry_storage.insert_telemetry(sample_record()) is True
    with connect_sqlite(telemetry_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == SQLITE_BUSY_TIMEOUT_MS
    assert telemetry_storage.count() == 1

    buffer_path = tmp_path / "buffer.db"
    buffer = TelemetryBuffer(buffer_path)
    record = sample_record("EDGE-BUFFER")
    assert buffer.add(record) is True
    with connect_sqlite(buffer_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == SQLITE_BUSY_TIMEOUT_MS
    assert buffer.peek()[0].record_id == record.record_id


def test_hub_sqlite_wal_busy_timeout_and_storage_round_trip(tmp_path):
    path = tmp_path / "hub.db"
    storage = HubStorage(path)
    storage.initialize()
    registry_edge = storage.register_edge("EDGE-HUB", "Hub Edge", "salt$hash")
    assert registry_edge.status == "OFFLINE"
    record = sample_record("EDGE-HUB")
    assert storage.insert_telemetry(record)
    with connect_sqlite(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == SQLITE_BUSY_TIMEOUT_MS
    assert storage.get_telemetry(record.record_id).record_id == record.record_id


def test_liveness_status_boundary_and_missing_values():
    now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
    timestamp = lambda age: (now - timedelta(seconds=age)).isoformat().replace("+00:00", "Z")
    assert edge_liveness_status(None, 60, now=now) == "OFFLINE"
    assert edge_liveness_status(timestamp(59), 60, now=now) == "ONLINE"
    assert edge_liveness_status(timestamp(60), 60, now=now) == "ONLINE"
    assert edge_liveness_status(timestamp(61), 60, now=now) == "OFFLINE"


def test_ingestion_refreshes_liveness_and_query_projection(tmp_path):
    storage = HubStorage(tmp_path / "live.db", edge_liveness_timeout_seconds=60)
    storage.register_edge("EDGE-LIVE", "Live Edge", "hash$only")
    assert storage.get_edge("EDGE-LIVE").status == "OFFLINE"
    storage.touch_edge("EDGE-LIVE")
    assert storage.get_edge("EDGE-LIVE").status == "ONLINE"
    assert storage.dashboard_edges()[0]["status"] == "ONLINE"

    old_seen = (datetime.now(timezone.utc) - timedelta(seconds=61)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(storage.database_path) as connection:
        connection.execute("UPDATE edges SET last_seen = ? WHERE sensor_id = ?", (old_seen, "EDGE-LIVE"))
    edge = storage.get_edge("EDGE-LIVE")
    assert edge.status == "OFFLINE"
    assert edge.last_seen == old_seen
    assert storage.dashboard_edges()[0]["status"] == "OFFLINE"


def test_authenticated_ingestion_refreshes_hub_and_dashboard_liveness(tmp_path, monkeypatch):
    monkeypatch.setenv("ROCKS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ROCKS_ADMIN_PASSWORD_HASH", hash_password("temporary-password"))
    monkeypatch.setenv("ROCKS_SESSION_SECRET", "temporary-session-secret")
    app = create_app(str(tmp_path / "hub-api.db"))
    service = app.state.hub_service
    _, api_key = service.registry.register("EDGE-API", "API Edge")
    service.storage.edge_liveness_timeout_seconds = 60
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {api_key}"}

    assert client.get("/api/v1/edges", headers=headers).json()[0]["status"] == "OFFLINE"
    record = sample_record("EDGE-API")
    ingested = client.post("/api/v1/telemetry", json=record.to_dict(), headers=headers)
    assert ingested.status_code == 200
    assert client.get("/api/v1/edges", headers=headers).json()[0]["status"] == "ONLINE"

    client.post("/dashboard/login", data={"username": "admin", "password": "temporary-password"})
    assert client.get("/api/v1/dashboard/edges").json()[0]["status"] == "ONLINE"
