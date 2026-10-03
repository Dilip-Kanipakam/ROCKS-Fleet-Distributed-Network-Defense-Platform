from __future__ import annotations

import errno
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry, telemetry_to_json
from rocks import sqlite as sqlite_module


def _record(record_id: str = "buffer-record"):
    features = TrafficFeatures(0, 60, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0)
    return replace(behavior_summary_telemetry(features, "SENSOR", device_id="DEVICE"), record_id=record_id)


def test_fresh_buffer_selects_valid_mode_for_filesystem(tmp_path):
    path = tmp_path / "fresh.db"
    buffer = TelemetryBuffer(path)
    with sqlite3.connect(path) as connection:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0].lower()

    filesystem = sqlite_module.filesystem_type_for_path(path)
    expected = "delete" if filesystem and filesystem.lower().startswith("ntfs") else "wal"
    assert mode == expected
    assert buffer.size() == 0


def test_linux_filesystem_keeps_wal_mode(tmp_path, monkeypatch):
    monkeypatch.setattr("rocks.edge.buffer.filesystem_type_for_path", lambda _path: "ext4")
    monkeypatch.setattr(sqlite_module, "filesystem_type_for_path", lambda _path: "ext4")
    path = tmp_path / "linux.db"

    TelemetryBuffer(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_ntfs_buffer_migrates_populated_wal_and_preserves_unstatable_shm(tmp_path, monkeypatch):
    path = tmp_path / "populated.db"
    record = _record("persisted-before-migration")
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            "CREATE TABLE buffer (sequence INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT UNIQUE NOT NULL, payload_json TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO buffer (record_id, payload_json) VALUES (?, ?)",
            (record.record_id, telemetry_to_json(record)),
        )
    connection.close()

    shm_path = tmp_path / "populated.db-shm"
    marker = b"preserve this sidecar entry"
    shm_path.write_bytes(marker)
    real_stat = os.stat

    def invalid_shm_stat(path_value, *args, **kwargs):
        if os.fspath(path_value) == os.fspath(shm_path):
            raise OSError(errno.EINVAL, "Invalid argument", os.fspath(shm_path))
        return real_stat(path_value, *args, **kwargs)

    monkeypatch.setattr("rocks.edge.buffer.filesystem_type_for_path", lambda _path: "ntfs3")
    monkeypatch.setattr(sqlite_module, "filesystem_type_for_path", lambda _path: "ntfs3")
    monkeypatch.setattr(sqlite_module.os, "stat", invalid_shm_stat)
    buffer = TelemetryBuffer(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
    assert [item.record_id for item in buffer.peek(10)] == [record.record_id]
    quarantined = list(tmp_path.glob("populated.db-shm.quarantine-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == marker
    assert path.is_file()


def test_ntfs_unmovable_shm_fails_without_changing_database_or_wal(tmp_path, monkeypatch):
    path = tmp_path / "blocked.db"
    wal_path = tmp_path / "blocked.db-wal"
    shm_path = tmp_path / "blocked.db-shm"
    original_database = b"database bytes remain untouched"
    original_wal = b"wal bytes remain untouched"
    path.write_bytes(original_database)
    wal_path.write_bytes(original_wal)
    shm_path.write_bytes(b"unreadable sidecar")
    real_stat = os.stat

    def invalid_shm_stat(path_value, *args, **kwargs):
        if os.fspath(path_value) == os.fspath(shm_path):
            raise OSError(errno.EINVAL, "Invalid argument", os.fspath(shm_path))
        return real_stat(path_value, *args, **kwargs)

    def invalid_shm_rename(_source, _destination):
        raise OSError(errno.EINVAL, "Invalid argument", os.fspath(shm_path))

    monkeypatch.setattr("rocks.edge.buffer.filesystem_type_for_path", lambda _path: "ntfs3")
    monkeypatch.setattr(sqlite_module.os, "stat", invalid_shm_stat)
    monkeypatch.setattr(sqlite_module.os, "rename", invalid_shm_rename)

    with pytest.raises(sqlite3.OperationalError, match="refusing to alter the database or WAL"):
        TelemetryBuffer(path)

    assert path.read_bytes() == original_database
    assert wal_path.read_bytes() == original_wal
    assert shm_path.read_bytes() == b"unreadable sidecar"


def test_populated_buffer_survives_reopen_and_sender_removal(tmp_path):
    path = tmp_path / "restart.db"
    first = _record("first")
    second = _record("second")
    buffer = TelemetryBuffer(path)
    assert buffer.add(first)
    assert buffer.add(second)

    reopened = TelemetryBuffer(path)
    assert [item.record_id for item in reopened.peek(10)] == ["first", "second"]
    assert reopened.remove("first") == 1
    assert TelemetryBuffer(path).peek(10)[0].record_id == "second"


def test_concurrent_add_keeps_buffer_within_configured_limit(tmp_path):
    buffer = TelemetryBuffer(tmp_path / "bounded.db", buffer_limit=12)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(buffer.add, _record(f"bounded-{index}"))
            for index in range(48)
        ]
        assert all(future.result() for future in futures)

    assert buffer.size() == 12
    retained_ids = [record.record_id for record in buffer.peek(20)]
    assert len(retained_ids) == 12
    assert len(retained_ids) == len(set(retained_ids))
    assert set(retained_ids) <= {f"bounded-{index}" for index in range(48)}


def test_transient_sqlite_open_error_is_retried(tmp_path, monkeypatch):
    path = tmp_path / "transient.db"
    buffer = TelemetryBuffer(path)
    original_connect = sqlite_module.connect_sqlite
    calls = 0

    def fail_once(database_path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("disk I/O error")
        return original_connect(database_path)

    monkeypatch.setattr("rocks.edge.buffer.connect_sqlite", fail_once)
    record = _record("after-transient-error")
    assert buffer.add(record)
    assert calls == 2
    assert buffer.peek()[0].record_id == record.record_id


def test_concurrent_producers_and_sender_keep_buffer_bounded(tmp_path):
    buffer = TelemetryBuffer(tmp_path / "concurrent.db", buffer_limit=20)
    workers = 4
    records_per_worker = 25
    start = threading.Barrier(workers + 1)
    producer_errors: list[BaseException] = []
    sender_errors: list[BaseException] = []
    producers_done = threading.Event()
    sent_ids: list[str] = []

    def produce(worker_id: int) -> None:
        try:
            start.wait()
            for index in range(records_per_worker):
                assert buffer.add(_record(f"producer-{worker_id}-{index}"))
        except BaseException as exc:
            producer_errors.append(exc)

    def send() -> None:
        try:
            start.wait()
            while not producers_done.is_set() or buffer.size():
                records = buffer.peek(7)
                if records:
                    for item in records:
                        if buffer.remove(item.record_id):
                            sent_ids.append(item.record_id)
                else:
                    time.sleep(0.001)
        except BaseException as exc:
            sender_errors.append(exc)

    with ThreadPoolExecutor(max_workers=workers + 1) as executor:
        futures = [executor.submit(produce, worker_id) for worker_id in range(workers)]
        sender_future = executor.submit(send)
        for future in futures:
            future.result()
        producers_done.set()
        sender_future.result()

    assert producer_errors == []
    assert sender_errors == []
    assert len(sent_ids) == len(set(sent_ids))
    assert buffer.size() <= 20