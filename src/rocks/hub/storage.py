from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from rocks.edge.telemetry import TelemetryRecord, telemetry_from_json, telemetry_to_json
from rocks.alerts.engine import Alert
from rocks.hub.models import EdgeInfo
from rocks.ml.analysis import AnalysisResult
from rocks.sqlite import connect_sqlite, enable_wal


class HubStorage:
    """Dedicated SQLite storage for Hub registry and central telemetry."""

    def __init__(self, database_path: str | Path, edge_liveness_timeout_seconds: int = 60) -> None:
        self.database_path = Path(database_path)
        self.edge_liveness_timeout_seconds = max(1, int(edge_liveness_timeout_seconds))

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            enable_wal(connection)
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
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    telemetry_id TEXT NOT NULL,
                    sensor_id TEXT NOT NULL,
                    device_id TEXT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    anomaly_score REAL,
                    retention_score REAL,
                    message TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    created_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    resolved_at TEXT,
                    UNIQUE (telemetry_id, alert_type)
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                """
            )
            self._ensure_alert_columns(connection)

    def _ensure_alert_columns(self, connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)").fetchall()}
        if "acknowledged_at" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT")
        if "resolved_at" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN resolved_at TEXT")
        connection.execute("UPDATE alerts SET status = 'OPEN' WHERE status IS NULL OR status = ''")

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
        return self._edge_info(row) if row else None

    def get_api_key_hash(self, sensor_id: str) -> str | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute("SELECT api_key_hash FROM edges WHERE sensor_id = ?", (sensor_id,)).fetchone()
        return str(row[0]) if row else None

    def list_edges(self) -> list[EdgeInfo]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute("SELECT sensor_id, name, status, created_at, last_seen FROM edges ORDER BY sensor_id").fetchall()
        return [self._edge_info(row) for row in rows]

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

    def telemetry_context(
        self,
        *,
        device_id: str | None = None,
        source_ip: str | None = None,
        sensor_id: str | None = None,
        event_type: str | None = None,
        since: str | None = None,
        until: str | None = None,
        telemetry_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return a bounded metadata-only telemetry context for investigation."""

        anchor: TelemetryRecord | None = None
        if telemetry_id:
            anchor = self.get_telemetry(telemetry_id)
            if anchor is None:
                return {"trigger": None, "related": []}
            device_id = device_id or anchor.device_id
            anchor_payload = anchor.payload
            source = anchor_payload.get("source") if isinstance(anchor_payload.get("source"), dict) else {}
            source_ip = source_ip or source.get("ip") or anchor_payload.get("source_ip")
            sensor_id = sensor_id or anchor.sensor_id

        if not device_id and not source_ip and not telemetry_id:
            raise ValueError("device_id or source_ip is required for telemetry context")

        clauses: list[str] = []
        parameters: list[Any] = []
        identity_clauses: list[str] = []
        if device_id:
            identity_clauses.append("device_id = ?")
            parameters.append(device_id)
        if source_ip:
            identity_clauses.extend(
                [
                    "json_extract(payload_json, '$.payload.source.ip') = ?",
                    "json_extract(payload_json, '$.payload.source_ip') = ?",
                    "(event_type = 'BEHAVIOR_SUMMARY' AND device_id LIKE ?)",
                ]
            )
            parameters.extend([source_ip, source_ip, f"{source_ip}|%"])
        if identity_clauses:
            clauses.append("(" + " OR ".join(identity_clauses) + ")")
        else:
            clauses.append("id = ?")
            parameters.append(telemetry_id)
        for column, value in (("sensor_id", sensor_id), ("event_type", event_type)):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if since is not None:
            clauses.append("timestamp >= ?")
            parameters.append(since)
        if until is not None:
            clauses.append("timestamp <= ?")
            parameters.append(until)
        bounded_limit = min(max(int(limit), 1), 100)
        parameters.append(bounded_limit)
        query = (
            "SELECT payload_json FROM telemetry WHERE "
            + " AND ".join(clauses)
            + " ORDER BY timestamp DESC, id DESC LIMIT ?"
        )
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        records = [telemetry_from_json(row[0]) for row in rows]
        return {
            "trigger": self._context_item(anchor) if anchor else None,
            "related": [self._context_item(record) for record in records],
        }

    @staticmethod
    def _context_item(record: TelemetryRecord) -> dict[str, Any]:
        payload = record.payload
        source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
        destination = payload.get("destination") if isinstance(payload.get("destination"), dict) else {}
        device_id = record.device_id
        device_source_ip = device_id.split("|", 1)[0] if device_id and "|" in device_id else None
        allowed_fields = (
            "packet_count",
            "bytes_sent",
            "bytes_received",
            "connection_duration_ms",
            "request_count",
            "failure_count",
            "window_seconds",
            "traffic_rate",
            "request_rate",
            "connection_count",
            "active_connections",
            "unique_destination_ip_count",
            "unique_destination_port_count",
            "repeated_destination_count",
            "dns_request_count",
            "dns_failure_count",
            "reconnect_count",
            "connection_failure_count",
        )
        item: dict[str, Any] = {
            "telemetry_id": record.record_id,
            "schema_version": record.schema_version,
            "timestamp": record.timestamp,
            "sensor_id": record.sensor_id,
            "device_id": record.device_id,
            "event_type": record.event_type,
            "source_ip": source.get("ip", payload.get("source_ip", device_source_ip)),
            "source_port": source.get("port", payload.get("source_port")),
            "destination_ip": destination.get("ip", payload.get("destination_ip")),
            "destination_port": destination.get("port", payload.get("destination_port")),
            "protocol": payload.get("protocol"),
        }
        item.update({key: payload[key] for key in allowed_fields if key in payload})
        return item

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

    def dashboard_edges(self) -> list[dict[str, Any]]:
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
        return [
            {
                **dict(row),
                "status": self._liveness_status(row["last_seen"]),
            }
            for row in rows
        ]

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
            byte_values = [payload.get("bytes_sent"), payload.get("bytes_received")]
            known_byte_values = [value for value in byte_values if isinstance(value, (int, float))]
            result.append(
                {
                    "timestamp": row[1],
                    "sensor_id": row[2],
                    "device_id": row[3],
                    "event_type": row[4],
                    "source_ip": source.get("ip", payload.get("source_ip")),
                    "destination_ip": destination.get("ip", payload.get("destination_ip")),
                    "protocol": payload.get("protocol"),
                    "bytes": sum(known_byte_values) if known_byte_values else None,
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

    def insert_alert(self, alert: Alert) -> bool:
        self.initialize()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO alerts
                (alert_id, telemetry_id, sensor_id, device_id, timestamp, alert_type,
                 severity, anomaly_score, retention_score, message, status, created_at,
                 acknowledged_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (alert.alert_id, alert.telemetry_id, alert.sensor_id, alert.device_id,
                 alert.timestamp, alert.alert_type, alert.severity, alert.anomaly_score,
                 alert.retention_score, alert.message, alert.status,
                 alert.created_at or _utc_now(), alert.acknowledged_at, alert.resolved_at),
            )
        return cursor.rowcount == 1

    def get_alert(self, alert_id: str) -> Alert | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT alert_id, telemetry_id, sensor_id, device_id, timestamp, alert_type, severity, anomaly_score, retention_score, message, status, created_at, acknowledged_at, resolved_at FROM alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        return Alert(
            alert_id=row["alert_id"],
            telemetry_id=row["telemetry_id"],
            sensor_id=row["sensor_id"],
            device_id=row["device_id"],
            timestamp=row["timestamp"],
            alert_type=row["alert_type"],
            severity=row["severity"],
            anomaly_score=row["anomaly_score"],
            retention_score=row["retention_score"],
            message=row["message"],
            status=row["status"],
            created_at=row["created_at"],
            acknowledged_at=row["acknowledged_at"],
            resolved_at=row["resolved_at"],
        )

    def update_alert_status(self, alert_id: str, new_status: str) -> Alert | None:
        self.initialize()
        current = self.get_alert(alert_id)
        if current is None:
            return None
        valid_transitions = {
            "OPEN": {"ACKNOWLEDGED", "RESOLVED"},
            "ACKNOWLEDGED": {"RESOLVED"},
            "RESOLVED": set(),
        }
        if current.status == new_status or new_status not in valid_transitions.get(current.status, set()):
            raise ValueError(f"Invalid alert transition: {current.status} -> {new_status}")

        now = _utc_now()
        field_updates = ["status = ?"]
        params: list[Any] = [new_status]
        if new_status == "ACKNOWLEDGED":
            field_updates.append("acknowledged_at = ?")
            params.append(current.acknowledged_at or now)
        if new_status == "RESOLVED":
            field_updates.append("resolved_at = ?")
            params.append(current.resolved_at or now)
        params.append(alert_id)

        with self._connect() as connection:
            connection.execute(f"UPDATE alerts SET {', '.join(field_updates)} WHERE alert_id = ?", params)
        return self.get_alert(alert_id)

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT alert_id, telemetry_id, sensor_id, device_id, timestamp, alert_type, severity, anomaly_score, retention_score, message, status, created_at, acknowledged_at, resolved_at FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (min(max(limit, 1), 100),),
            ).fetchall()
        return [dict(row) for row in rows]

    def alert_counts(self) -> dict[str, int]:
        self.initialize()
        with self._connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            high = connection.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'").fetchone()[0]
            warning = connection.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'WARNING'").fetchone()[0]
            open_count = connection.execute("SELECT COUNT(*) FROM alerts WHERE status = 'OPEN'").fetchone()[0]
        return {"total_recent": int(total), "high": int(high), "warning": int(warning), "open": int(open_count)}

    def _connect(self) -> sqlite3.Connection:
        connection = connect_sqlite(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _edge_info(self, row: sqlite3.Row) -> EdgeInfo:
        return EdgeInfo(
            sensor_id=row["sensor_id"],
            name=row["name"],
            status=self._liveness_status(row["last_seen"]),
            created_at=row["created_at"],
            last_seen=row["last_seen"],
        )

    def _liveness_status(self, last_seen: str | None) -> str:
        return edge_liveness_status(last_seen, self.edge_liveness_timeout_seconds)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def edge_liveness_status(
    last_seen: str | None,
    timeout_seconds: int,
    *,
    now: datetime | None = None,
) -> str:
    if not last_seen:
        return "OFFLINE"
    try:
        seen_at = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return "OFFLINE"
    reference_time = now or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)
    age_seconds = (reference_time.astimezone(timezone.utc) - seen_at.astimezone(timezone.utc)).total_seconds()
    return "ONLINE" if 0 <= age_seconds <= max(1, timeout_seconds) else "OFFLINE"
