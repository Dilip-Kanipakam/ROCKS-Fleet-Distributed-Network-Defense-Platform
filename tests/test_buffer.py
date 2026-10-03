from __future__ import annotations

import os

from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry


def record():
    features = TrafficFeatures(0.0, 60.0, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0)
    return behavior_summary_telemetry(features, "SENSOR", device_id="DEVICE")


def test_buffer_fifo_duplicate_and_remove(tmp_path):
    buffer = TelemetryBuffer(tmp_path / "buffer.db")
    first = record()
    assert buffer.add(first) is True
    assert buffer.add(first) is False
    assert buffer.size() == 1
    assert buffer.peek()[0].record_id == first.record_id
    assert buffer.remove() == 1
    assert buffer.size() == 0


def test_buffer_persists_across_reopen(tmp_path):
    path = tmp_path / "buffer.db"
    buffer = TelemetryBuffer(path)
    first = record()
    assert buffer.add(first) is True
    reopened = TelemetryBuffer(path)
    assert reopened.size() == 1
    assert reopened.peek(1)[0].record_id == first.record_id
    assert reopened.remove(first.record_id) == 1
    assert reopened.size() == 0


def test_full_buffer_evicts_oldest_and_persists_drop_count(tmp_path):
    path = tmp_path / "bounded-buffer.db"
    buffer = TelemetryBuffer(path, buffer_limit=2)
    first = record()
    second = behavior_summary_telemetry(
        TrafficFeatures(0.0, 60.0, 2, 120, 120, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 2.0, 2.0),
        "SENSOR",
        device_id="DEVICE-2",
    )
    third = behavior_summary_telemetry(
        TrafficFeatures(0.0, 60.0, 3, 180, 180, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 3.0, 3.0),
        "SENSOR",
        device_id="DEVICE-3",
    )

    assert buffer.add(first)
    assert buffer.add(second)
    assert buffer.add(third)

    reopened = TelemetryBuffer(path, buffer_limit=2)
    assert reopened.size() == 2
    assert [item.record_id for item in reopened.peek(10)] == [second.record_id, third.record_id]
    assert reopened.dropped_records == 1


def test_health_warns_on_persistent_buffer_evictions(tmp_path):
    from rocks.health import HealthChecker, HealthStatus

    path = tmp_path / "health-buffer.db"
    buffer = TelemetryBuffer(path, buffer_limit=1)
    buffer.add(record())
    buffer.add(
        behavior_summary_telemetry(
            TrafficFeatures(0.0, 60.0, 2, 120, 120, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 2.0, 2.0),
            "SENSOR",
            device_id="DEVICE-2",
        )
    )

    check = HealthChecker._buffer_check(None, path)

    assert check.status == HealthStatus.WARNING
    assert check.details["dropped_records"] == 1


def test_buffer_can_peek_records_for_one_sensor_without_reordering_others(tmp_path):
    buffer = TelemetryBuffer(tmp_path / "sensor-filter.db")
    first = record()
    other = behavior_summary_telemetry(
        TrafficFeatures(0, 60, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0),
        "OTHER-SENSOR",
        device_id="DEVICE",
    )
    buffer.add(other)
    buffer.add(first)

    assert [item.sensor_id for item in buffer.peek(10, sensor_id="SENSOR")] == ["SENSOR"]
    assert [item.sensor_id for item in buffer.peek(10)] == ["OTHER-SENSOR", "SENSOR"]


def test_repeated_buffer_access_closes_sqlite_descriptors(tmp_path):
    descriptor_directory = "/proc/self/fd"
    if not os.path.isdir(descriptor_directory):
        return
    buffer = TelemetryBuffer(tmp_path / "descriptor-check.db")
    buffer.add(record())
    before = len(os.listdir(descriptor_directory))

    for _ in range(50):
        assert buffer.peek(1)
        assert buffer.remove(limit=1) == 1
        buffer.add(record())

    after = len(os.listdir(descriptor_directory))
    assert after <= before + 1
