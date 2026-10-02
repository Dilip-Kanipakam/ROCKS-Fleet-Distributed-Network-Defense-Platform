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
