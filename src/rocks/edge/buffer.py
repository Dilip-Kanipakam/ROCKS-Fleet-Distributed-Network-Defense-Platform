from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from rocks.config import get_buffer_path, validate_positive_integer
from rocks.edge.telemetry import TelemetryRecord, telemetry_from_json, telemetry_to_json
from rocks.logging_config import configure_logging
from rocks.sqlite import (
    connect_sqlite,
    enable_edge_buffer_journal,
    filesystem_type_for_path,
    quarantine_unstatable_shm,
    retry_sqlite_io,
)


class TelemetryBuffer:
    """Persistent local FIFO buffer with no Hub or networking behavior."""

    def __init__(self, database_path: str | Path | None = None, *, buffer_limit: int = 10_000) -> None:
        self.database_path = Path(database_path) if database_path is not None else get_buffer_path()
        self.buffer_limit = validate_positive_integer(buffer_limit, field="buffer_limit")
        self._logger = configure_logging()
        self.initialize()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if (filesystem_type_for_path(self.database_path) or "").lower().startswith("ntfs"):
            quarantined_shm = quarantine_unstatable_shm(self.database_path)
            if quarantined_shm is not None:
                self._logger.warning("Preserved unreadable SQLite SHM sidecar at %s", quarantined_shm)
        retry_sqlite_io(self._initialize_once)

    def _initialize_once(self) -> None:
        with self._connect() as connection:
            enable_edge_buffer_journal(connection, self.database_path)
            connection.execute(
                "CREATE TABLE IF NOT EXISTS buffer (sequence INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT UNIQUE NOT NULL, payload_json TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS buffer_stats (id INTEGER PRIMARY KEY CHECK (id = 1), dropped_records INTEGER NOT NULL DEFAULT 0, dropped_packets INTEGER NOT NULL DEFAULT 0)"
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(buffer_stats)")}
            if "dropped_packets" not in columns:
                connection.execute("ALTER TABLE buffer_stats ADD COLUMN dropped_packets INTEGER NOT NULL DEFAULT 0")
            connection.execute("INSERT OR IGNORE INTO buffer_stats (id, dropped_records) VALUES (1, 0)")

    def add(self, record: TelemetryRecord) -> bool:
        try:
            dropped = retry_sqlite_io(lambda: self._add_once(record))
        except sqlite3.IntegrityError:
            self._logger.info("Duplicate telemetry ignored in buffer: %s", record.record_id)
            return False
        if dropped:
            self._logger.error(
                "EDGE_BUFFER_OVERFLOW dropped_records=%s total_dropped_records=%s",
                dropped,
                self.dropped_records,
            )
        self._logger.debug("Telemetry added to local buffer: %s", record.record_id)
        return True

    def _add_once(self, record: TelemetryRecord) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(connection.execute("SELECT COUNT(*) FROM buffer").fetchone()[0])
            overflow = 0
            if count >= self.buffer_limit:
                overflow = count - self.buffer_limit + 1
                connection.execute(
                    "DELETE FROM buffer WHERE sequence IN (SELECT sequence FROM buffer ORDER BY sequence ASC LIMIT ?)",
                    (overflow,),
                )
                connection.execute(
                    "UPDATE buffer_stats SET dropped_records = dropped_records + ? WHERE id = 1",
                    (overflow,),
                )
            connection.execute(
                "INSERT INTO buffer (record_id, payload_json) VALUES (?, ?)",
                (record.record_id, telemetry_to_json(record)),
            )
            return overflow

    def peek(self, limit: int = 1, *, sensor_id: str | None = None) -> list[TelemetryRecord]:
        if limit <= 0:
            return []
        return retry_sqlite_io(lambda: self._peek_once(limit, sensor_id=sensor_id))

    def _peek_once(self, limit: int, *, sensor_id: str | None) -> list[TelemetryRecord]:
        with self._connect() as connection:
            if sensor_id is None:
                rows = connection.execute(
                    "SELECT payload_json FROM buffer ORDER BY sequence ASC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload_json FROM buffer WHERE json_extract(payload_json, '$.sensor_id') = ? ORDER BY sequence ASC LIMIT ?",
                    (sensor_id, limit),
                ).fetchall()
        return [telemetry_from_json(row[0]) for row in rows]

    def remove(self, record_id: str | None = None, limit: int = 1) -> int:
        if record_id is None and limit <= 0:
            return 0
        return retry_sqlite_io(lambda: self._remove_once(record_id, limit))

    def _remove_once(self, record_id: str | None, limit: int) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if record_id is not None:
                cursor = connection.execute("DELETE FROM buffer WHERE record_id = ?", (record_id,))
            else:
                ids = connection.execute(
                    "SELECT record_id FROM buffer ORDER BY sequence ASC LIMIT ?", (limit,)
                ).fetchall()
                cursor = None
                for row in ids:
                    cursor = connection.execute("DELETE FROM buffer WHERE record_id = ?", (row[0],))
                if cursor is None:
                    return 0
                return len(ids)
            return cursor.rowcount

    def size(self) -> int:
        return retry_sqlite_io(self._size_once)

    def _size_once(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM buffer").fetchone()[0])

    @property
    def dropped_records(self) -> int:
        return retry_sqlite_io(self._dropped_records_once)

    def _dropped_records_once(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT dropped_records FROM buffer_stats WHERE id = 1").fetchone()
            return int(row[0]) if row else 0

    def record_dropped_packets(self, count: int) -> None:
        if count > 0:
            retry_sqlite_io(lambda: self._record_dropped_packets_once(count))

    def _record_dropped_packets_once(self, count: int) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE buffer_stats SET dropped_packets = dropped_packets + ? WHERE id = 1",
                (count,),
            )

    @property
    def dropped_packets(self) -> int:
        return retry_sqlite_io(self._dropped_packets_once)

    def _dropped_packets_once(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT dropped_packets FROM buffer_stats WHERE id = 1").fetchone()
            return int(row[0]) if row else 0

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = connect_sqlite(self.database_path)
        try:
            with connection:
                yield connection
        finally:
            connection.close()
