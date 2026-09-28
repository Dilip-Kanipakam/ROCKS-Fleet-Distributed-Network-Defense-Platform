from __future__ import annotations

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
