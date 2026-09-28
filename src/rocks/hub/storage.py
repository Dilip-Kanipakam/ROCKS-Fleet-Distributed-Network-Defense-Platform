from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rocks.edge.telemetry import TelemetryRecord, telemetry_from_json, telemetry_to_json
from rocks.hub.models import EdgeInfo


class HubStorage:
    """Dedicated SQLite storage for Hub registry and central telemetry."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS edges (
                    sensor_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen TEXT,
                    api_key_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS telemetry (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    sensor_id TEXT NOT NULL,
                    device_id TEXT,
                    event_type TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_hub_telemetry_timestamp ON telemetry(timestamp);
                CREATE INDEX IF NOT EXISTS idx_hub_telemetry_sensor_id ON telemetry(sensor_id);
                CREATE INDEX IF NOT EXISTS idx_hub_telemetry_device_id ON telemetry(device_id);
                CREATE INDEX IF NOT EXISTS idx_hub_telemetry_event_type ON telemetry(event_type);
                CREATE INDEX IF NOT EXISTS idx_hub_telemetry_sensor_timestamp ON telemetry(sensor_id, timestamp);
                """
            )

    def register_edge(self, sensor_id: str, name: str, api_key_hash: str) -> EdgeInfo:
        self.initialize()
        created_at = _utc_now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO edges (sensor_id, name, status, created_at, last_seen, api_key_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (sensor_id, name, "registered", created_at, None, api_key_hash),
            )
        return self.get_edge(sensor_id)  # type: ignore[return-value]

    def get_edge(self, sensor_id: str) -> EdgeInfo | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT sensor_id, name, status, created_at, last_seen FROM edges WHERE sensor_id = ?",
                (sensor_id,),
            ).fetchone()
        return EdgeInfo(*row) if row else None

    def get_api_key_hash(self, sensor_id: str) -> str | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute("SELECT api_key_hash FROM edges WHERE sensor_id = ?", (sensor_id,)).fetchone()
        return str(row[0]) if row else None

    def list_edges(self) -> list[EdgeInfo]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute("SELECT sensor_id, name, status, created_at, last_seen FROM edges ORDER BY sensor_id").fetchall()
        return [EdgeInfo(*row) for row in rows]

    def touch_edge(self, sensor_id: str) -> None:
        self.initialize()
        with self._connect() as connection:
            connection.execute("UPDATE edges SET status = ?, last_seen = ? WHERE sensor_id = ?", ("online", _utc_now(), sensor_id))

    def insert_telemetry(self, record: TelemetryRecord) -> bool:
        self.initialize()
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO telemetry (id, timestamp, sensor_id, device_id, event_type, schema_version, payload_json, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (record.record_id, record.timestamp, record.sensor_id, record.device_id, record.event_type, record.schema_version, telemetry_to_json(record), _utc_now()),
                )
        except sqlite3.IntegrityError as exc:
            with self._connect() as connection:
                exists = connection.execute("SELECT 1 FROM telemetry WHERE id = ?", (record.record_id,)).fetchone()
            if exists:
                return False
            raise exc
        return True

    def get_telemetry(self, telemetry_id: str) -> TelemetryRecord | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute("SELECT payload_json FROM telemetry WHERE id = ?", (telemetry_id,)).fetchone()
        return telemetry_from_json(row[0]) if row else None

    def query_telemetry(self, *, sensor_id: str | None = None, device_id: str | None = None, event_type: str | None = None, limit: int = 100) -> list[TelemetryRecord]:
        self.initialize()
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (("sensor_id", sensor_id), ("device_id", device_id), ("event_type", event_type)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self._connect() as connection:
            rows = connection.execute(f"SELECT payload_json FROM telemetry{where} ORDER BY timestamp DESC LIMIT ?", values).fetchall()
        return [telemetry_from_json(row[0]) for row in rows]

    def count(self) -> int:
        self.initialize()
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0])

    def event_type_counts(self) -> dict[str, int]:
        self.initialize()
        with self._connect() as connection:
            return {str(row[0]): int(row[1]) for row in connection.execute("SELECT event_type, COUNT(*) FROM telemetry GROUP BY event_type")}

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
