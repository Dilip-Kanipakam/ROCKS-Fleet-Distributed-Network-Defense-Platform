from __future__ import annotations

import sqlite3
from pathlib import Path

SQLITE_BUSY_TIMEOUT_MS = 5000


def connect_sqlite(database_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        database_path,
        timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
    )
    connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    return connection


def enable_wal(connection: sqlite3.Connection) -> None:
    current_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
    if current_mode != "wal" and database_path_is_file(connection):
        connection.execute("PRAGMA journal_mode=WAL")


def database_path_is_file(connection: sqlite3.Connection) -> str:
    row = connection.execute("PRAGMA database_list").fetchone()
    return str(row[2]) if row else ""