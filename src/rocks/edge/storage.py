from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from rocks.config import get_storage_path
from rocks.edge.telemetry import TelemetryRecord, telemetry_from_json, telemetry_to_json
from rocks.logging_config import configure_logging
from rocks.sqlite import connect_sqlite, enable_wal


class TelemetryStorage:
    """SQLite storage for metadata-only telemetry records."""

    def __init__(self, database_path: str | Path | None = None) -> None:
        self.database_path = Path(database_path) if database_path is not None else get_storage_path()
        self._logger = configure_logging()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            enable_wal(connection)
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS telemetry (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    sensor_id TEXT NOT NULL,
                    device_id TEXT,
                    event_type TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    retention_priority INTEGER,
                    retention_reason TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry(timestamp);
                CREATE INDEX IF NOT EXISTS idx_telemetry_sensor_id ON telemetry(sensor_id);
                CREATE INDEX IF NOT EXISTS idx_telemetry_device_id ON telemetry(device_id);
                CREATE INDEX IF NOT EXISTS idx_telemetry_event_type ON telemetry(event_type);
                """
            )
        self._logger.debug("Edge telemetry storage initialized at %s", self.database_path)

    def insert_telemetry(self, record: TelemetryRecord) -> bool:
        self.initialize()
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO telemetry
                    (id, timestamp, sensor_id, device_id, event_type, schema_version,
                     payload_json, retention_priority, retention_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.record_id,
                        record.timestamp,
                        record.sensor_id,
                        record.device_id,
                        record.event_type,
                        record.schema_version,
                        telemetry_to_json(record),
                        record.retention_priority,
                        record.retention_reason,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            with self._connect() as connection:
                existing = connection.execute("SELECT id FROM telemetry WHERE id = ?", (record.record_id,)).fetchone()
            if existing:
                self._logger.info("Duplicate telemetry ignored: %s", record.record_id)
                return False
            raise exc
        self._logger.debug("Telemetry stored: %s", record.record_id)
        return True

    def insert_many(self, records: Iterable[TelemetryRecord]) -> int:
        return sum(self.insert_telemetry(record) for record in records)

    def get_recent(self, limit: int = 100) -> list[TelemetryRecord]:
        if limit <= 0:
            return []
        return self._query("SELECT payload_json FROM telemetry ORDER BY timestamp DESC, rowid DESC LIMIT ?", (limit,))

    def get_by_device(self, device_id: str, limit: int = 100) -> list[TelemetryRecord]:
        return self._query("SELECT payload_json FROM telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?", (device_id, limit))

    def get_by_event_type(self, event_type: str, limit: int = 100) -> list[TelemetryRecord]:
        return self._query("SELECT payload_json FROM telemetry WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?", (event_type, limit))

    def get_since(self, timestamp: str | datetime, limit: int = 1000) -> list[TelemetryRecord]:
        value = timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp
        return self._query("SELECT payload_json FROM telemetry WHERE timestamp >= ? ORDER BY timestamp ASC LIMIT ?", (value, limit))

    def count(self) -> int:
        self.initialize()
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0])

    def delete_before(self, timestamp: str | datetime) -> int:
        value = timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp
        self.initialize()
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM telemetry WHERE timestamp < ?", (value,))
            return cursor.rowcount

    def close(self) -> None:
        return None

    def _query(self, query: str, parameters: tuple[object, ...]) -> list[TelemetryRecord]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [telemetry_from_json(row[0]) for row in rows]

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = connect_sqlite(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
