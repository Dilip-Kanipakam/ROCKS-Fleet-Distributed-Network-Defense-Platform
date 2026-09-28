from __future__ import annotations

from pathlib import Path

from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.features import TrafficFeatures
from rocks.edge.sender import EdgeSender
from rocks.edge.telemetry import behavior_summary_telemetry


def record():
    features = TrafficFeatures(0, 60, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0)
    return behavior_summary_telemetry(features, "EDGE-01")


def test_sender_removes_only_acknowledged_records(tmp_path, monkeypatch):
    buffer = TelemetryBuffer(tmp_path / "buffer.db")
    telemetry = record()
    buffer.add(telemetry)
    sender = EdgeSender("http://127.0.0.1:8000", "test-key")

    monkeypatch.setattr(sender, "send_record", lambda _record: True)
    result = sender.send_pending(buffer)
    assert result.sent == 1
    assert result.failed == 0
    assert buffer.size() == 0

    buffer.add(telemetry)
    monkeypatch.setattr(sender, "send_record", lambda _record: False)
    result = sender.send_pending(buffer)
    assert result.sent == 0
    assert result.failed == 1
    assert buffer.size() == 1
