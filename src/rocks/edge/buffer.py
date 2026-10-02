from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from rocks.config import get_buffer_path, validate_positive_integer
from rocks.edge.telemetry import TelemetryRecord, telemetry_from_json, telemetry_to_json
from rocks.logging_config import configure_logging
from rocks.sqlite import connect_sqlite, enable_wal


class TelemetryBuffer:
    """Persistent local FIFO buffer with no Hub or networking behavior."""

    def __init__(self, database_path: str | Path | None = None, *, buffer_limit: int = 10_000) -> None:
        self.database_path = Path(database_path) if database_path is not None else get_buffer_path()
        self.buffer_limit = validate_positive_integer(buffer_limit, field="buffer_limit")
        self._logger = configure_logging()
        self.initialize()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            enable_wal(connection)
            connection.execute(
                "CREATE TABLE IF NOT EXISTS buffer (sequence INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT UNIQUE NOT NULL, payload_json TEXT NOT NULL)"
            )

    def add(self, record: TelemetryRecord) -> bool:
        try:
            with self._connect() as connection:
                count = int(connection.execute("SELECT COUNT(*) FROM buffer").fetchone()[0])
                if count >= self.buffer_limit:
                    overflow = count - self.buffer_limit + 1
                    connection.execute(
                        "DELETE FROM buffer WHERE sequence IN (SELECT sequence FROM buffer ORDER BY sequence ASC LIMIT ?)",
                        (overflow,),
                    )
                connection.execute(
                    "INSERT INTO buffer (record_id, payload_json) VALUES (?, ?)",
                    (record.record_id, telemetry_to_json(record)),
                )
        except sqlite3.IntegrityError:
            self._logger.info("Duplicate telemetry ignored in buffer: %s", record.record_id)
            return False
        self._logger.debug("Telemetry added to local buffer: %s", record.record_id)
        return True

    def peek(self, limit: int = 1, *, sensor_id: str | None = None) -> list[TelemetryRecord]:
        if limit <= 0:
            return []
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
        with self._connect() as connection:
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
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM buffer").fetchone()[0])

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = connect_sqlite(self.database_path)
        try:
            with connection:
                yield connection
        finally:
            connection.close()
