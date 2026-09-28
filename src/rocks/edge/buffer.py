from __future__ import annotations

import sqlite3
from pathlib import Path

from rocks.config import get_buffer_path
from rocks.edge.telemetry import TelemetryRecord, telemetry_from_json, telemetry_to_json
from rocks.logging_config import configure_logging


class TelemetryBuffer:
    """Persistent local FIFO buffer with no Hub or networking behavior."""

    def __init__(self, database_path: str | Path | None = None) -> None:
        self.database_path = Path(database_path) if database_path is not None else get_buffer_path()
        self._logger = configure_logging()
        self.initialize()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS buffer (sequence INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT UNIQUE NOT NULL, payload_json TEXT NOT NULL)"
            )

    def add(self, record: TelemetryRecord) -> bool:
        try:
            with sqlite3.connect(self.database_path) as connection:
                connection.execute(
                    "INSERT INTO buffer (record_id, payload_json) VALUES (?, ?)",
                    (record.record_id, telemetry_to_json(record)),
                )
        except sqlite3.IntegrityError:
            self._logger.info("Duplicate telemetry ignored in buffer: %s", record.record_id)
            return False
        self._logger.debug("Telemetry added to local buffer: %s", record.record_id)
        return True

    def peek(self, limit: int = 1) -> list[TelemetryRecord]:
        if limit <= 0:
            return []
        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                "SELECT payload_json FROM buffer ORDER BY sequence ASC LIMIT ?", (limit,)
            ).fetchall()
        return [telemetry_from_json(row[0]) for row in rows]

    def remove(self, record_id: str | None = None, limit: int = 1) -> int:
        with sqlite3.connect(self.database_path) as connection:
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
        with sqlite3.connect(self.database_path) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM buffer").fetchone()[0])
