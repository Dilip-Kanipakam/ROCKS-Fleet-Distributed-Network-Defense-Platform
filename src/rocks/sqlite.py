from __future__ import annotations

import errno
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Callable, TypeVar

SQLITE_BUSY_TIMEOUT_MS = 5000
SQLITE_IO_RETRY_ATTEMPTS = 3
_T = TypeVar("_T")


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


def filesystem_type_for_path(path: str | Path) -> str | None:
    """Return the Linux filesystem type mounting path, when available."""
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.is_file():
        return None

    target = Path(path).resolve(strict=False)
    matches: list[tuple[int, str]] = []
    try:
        lines = mountinfo.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = Path(_unescape_mount_field(fields[4]))
            filesystem_type = fields[separator + 1]
        except (IndexError, ValueError):
            continue
        if target == mount_point or mount_point in target.parents:
            matches.append((len(str(mount_point)), filesystem_type))
    return max(matches, default=(0, ""))[1] or None


def quarantine_unstatable_shm(database_path: str | Path) -> Path | None:
    """Preserve an SHM entry that NTFS reports as invalid before SQLite opens it."""
    shm_path = Path(f"{database_path}-shm")
    try:
        os.stat(shm_path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno != errno.EINVAL:
            raise
        quarantine_path = Path(f"{shm_path}.quarantine-{uuid.uuid4().hex}")
        try:
            os.rename(shm_path, quarantine_path)
        except OSError as rename_error:
            raise sqlite3.OperationalError(
                f"Cannot preserve unreadable SQLite SHM sidecar {shm_path}; refusing to alter the database or WAL"
            ) from rename_error
        return quarantine_path
    return None


def enable_edge_buffer_journal(connection: sqlite3.Connection, database_path: str | Path) -> str:
    """Use rollback journaling for NTFS Edge buffers and WAL elsewhere."""
    if (filesystem_type_for_path(database_path) or "").lower().startswith("ntfs"):
        mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower()
        if mode != "delete":
            raise sqlite3.OperationalError(f"SQLite selected unexpected journal mode: {mode}")
        return mode
    enable_wal(connection)
    return str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()


def retry_sqlite_io(operation: Callable[[], _T], *, attempts: int = SQLITE_IO_RETRY_ATTEMPTS) -> _T:
    """Retry bounded transient SQLite I/O, locking, and open errors; surface exhaustion."""
    retry_codes = {
        getattr(sqlite3, name)
        for name in ("SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_IOERR", "SQLITE_CANTOPEN")
        if hasattr(sqlite3, name)
    }
    for attempt in range(attempts):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            code = getattr(exc, "sqlite_errorcode", None)
            primary_code = code & 0xFF if isinstance(code, int) else None
            transient_message = any(
                marker in str(exc).lower()
                for marker in ("disk i/o error", "database is locked", "unable to open database file")
            )
            if attempt + 1 >= attempts or (primary_code not in retry_codes and not transient_message):
                raise
            time.sleep(0.05 * (attempt + 1))
    raise AssertionError("unreachable")


def database_path_is_file(connection: sqlite3.Connection) -> str:
    row = connection.execute("PRAGMA database_list").fetchone()
    return str(row[2]) if row else ""


def _unescape_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)