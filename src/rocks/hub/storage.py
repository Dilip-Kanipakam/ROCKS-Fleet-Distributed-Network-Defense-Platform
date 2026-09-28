from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from rocks.edge.telemetry import TelemetryRecord, telemetry_from_json, telemetry_to_json
from rocks.hub.models import EdgeInfo
from rocks.ml.analysis import AnalysisResult


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
                CREATE TABLE IF NOT EXISTS telemetry_analysis (
                    telemetry_id TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    baseline_status TEXT NOT NULL,
                    expected_traffic REAL,
                    actual_traffic REAL NOT NULL,
                    deviation REAL,
                    anomaly_score REAL,
                    retention_score REAL,
                    retention_priority TEXT,
                    analyzed_at TEXT NOT NULL,
                    PRIMARY KEY (telemetry_id, model_version)
                );
                CREATE INDEX IF NOT EXISTS idx_analysis_anomaly_score ON telemetry_analysis(anomaly_score);
                CREATE INDEX IF NOT EXISTS idx_analysis_retention_priority ON telemetry_analysis(retention_priority);
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

    def recent_count(self, seconds: int = 300) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")
        self.initialize()
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM telemetry WHERE timestamp >= ?", (cutoff,)).fetchone()[0])

    def analysis_count(self) -> int:
        self.initialize()
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM telemetry_analysis").fetchone()[0])

    def recent_analysis(self, limit: int = 50) -> list[dict[str, Any]]:
        self.initialize()
        bounded_limit = min(max(limit, 1), 100)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT a.telemetry_id, t.timestamp, t.sensor_id, t.device_id,
                       a.actual_traffic, a.expected_traffic, a.anomaly_score,
                       a.retention_score, a.retention_priority, a.baseline_status
                FROM telemetry_analysis AS a
                JOIN telemetry AS t ON t.id = a.telemetry_id
                ORDER BY t.timestamp DESC LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_edges(self, online_seconds: int = 300) -> list[dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=online_seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT e.sensor_id, e.name, e.status, e.created_at, e.last_seen,
                       COUNT(t.id) AS telemetry_count
                FROM edges AS e
                LEFT JOIN telemetry AS t ON t.sensor_id = e.sensor_id
                GROUP BY e.sensor_id, e.name, e.status, e.created_at, e.last_seen
                ORDER BY e.sensor_id
                """
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["status"] = "online" if row["status"] == "online" and row["last_seen"] and row["last_seen"] >= cutoff else "offline"
            result.append(item)
        return result

    def dashboard_telemetry(
        self,
        *,
        limit: int = 50,
        event_type: str | None = None,
        sensor_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self.initialize()
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (("event_type", event_type), ("sensor_id", sensor_id)):
            if value is not None:
                clauses.append(f"t.{column} = ?")
                values.append(value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(min(max(limit, 1), 100))
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT t.payload_json, t.timestamp, t.sensor_id, t.device_id, t.event_type FROM telemetry AS t{where} ORDER BY t.timestamp DESC LIMIT ?",
                values,
            ).fetchall()
        result = []
        for row in rows:
            record = telemetry_from_json(row[0])
            payload = record.payload
            source = payload.get("source", {}) if isinstance(payload.get("source"), dict) else {}
            destination = payload.get("destination", {}) if isinstance(payload.get("destination"), dict) else {}
            result.append(
                {
                    "timestamp": row[1],
                    "sensor_id": row[2],
                    "device_id": row[3],
                    "event_type": row[4],
                    "source_ip": source.get("ip", payload.get("source_ip")),
                    "destination_ip": destination.get("ip", payload.get("destination_ip")),
                    "protocol": payload.get("protocol"),
                    "bytes": payload.get("bytes_sent", 0) + payload.get("bytes_received", 0),
                    "telemetry_id": record.record_id,
                }
            )
        return result

    def traffic_points(self, limit: int = 20) -> list[dict[str, Any]]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT t.timestamp, json_extract(t.payload_json, '$.bytes_sent') +
                       json_extract(t.payload_json, '$.bytes_received') AS actual_traffic,
                       a.expected_traffic
                FROM telemetry AS t
                LEFT JOIN telemetry_analysis AS a ON a.telemetry_id = t.id
                WHERE t.event_type = 'BEHAVIOR_SUMMARY'
                ORDER BY t.timestamp DESC LIMIT ?
                """,
                (min(max(limit, 1), 100),),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def insert_analysis(self, result: AnalysisResult) -> bool:
        self.initialize()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO telemetry_analysis
                (telemetry_id, model_version, baseline_status, expected_traffic,
                 actual_traffic, deviation, anomaly_score, retention_score,
                 retention_priority, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.telemetry_id,
                    result.model_version,
                    result.baseline_status,
                    result.expected_traffic,
                    result.actual_traffic,
                    result.deviation,
                    result.anomaly_score,
                    result.retention_score,
                    result.retention_priority,
                    result.analyzed_at,
                ),
            )
        return cursor.rowcount == 1

    def get_analysis(self, telemetry_id: str, model_version: str) -> AnalysisResult | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT telemetry_id, model_version, baseline_status, expected_traffic, actual_traffic, deviation, anomaly_score, retention_score, retention_priority, analyzed_at FROM telemetry_analysis WHERE telemetry_id = ? AND model_version = ?",
                (telemetry_id, model_version),
            ).fetchone()
        if row is None:
            return None
        record = self.get_telemetry(telemetry_id)
        if record is None:
            return None
        return AnalysisResult(
            telemetry_id=row[0],
            sensor_id=record.sensor_id,
            device_id=record.device_id,
            timestamp=record.timestamp,
            model_version=row[1],
            baseline_status=row[2],
            expected_traffic=row[3],
            actual_traffic=row[4],
            deviation=row[5],
            anomaly_score=row[6],
            retention_score=row[7],
            retention_priority=row[8],
            analyzed_at=row[9],
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
