from __future__ import annotations

import io
import threading
from pathlib import Path

from fastapi.testclient import TestClient

from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.features import TrafficFeatures
from rocks.edge.sender import EdgeSender
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.hub.app import create_app
from rocks.simulator.generator import Scenario, generate_records


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


def test_sender_empty_batch_is_a_successful_noop(tmp_path):
    buffer = TelemetryBuffer(tmp_path / "empty-buffer.db")
    sender = EdgeSender("http://127.0.0.1:8000", "test-key")

    result = sender.send_pending(buffer)

    assert result.sent == 0
    assert result.failed == 0


def test_sender_skips_other_sensor_records_and_sends_matching_identity(tmp_path, monkeypatch):
    buffer = TelemetryBuffer(tmp_path / "mixed-sensor-buffer.db")
    buffer.add(
        behavior_summary_telemetry(
            TrafficFeatures(0, 60, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0),
            "STALE-SENSOR",
        )
    )
    matching = record()
    buffer.add(matching)
    sender = EdgeSender("http://127.0.0.1:8000", "test-key")
    sent_ids = []
    monkeypatch.setattr(sender, "send_record", lambda item: sent_ids.append(item.record_id) or True)

    result = sender.send_pending(buffer, sensor_id="EDGE-01")

    assert result.sent == 1
    assert result.failed == 0
    assert sent_ids == [matching.record_id]
    assert [item.sensor_id for item in buffer.peek(10)] == ["STALE-SENSOR"]


def test_sender_sends_bounded_batch_concurrently_and_removes_only_successes(tmp_path, monkeypatch):
    buffer = TelemetryBuffer(tmp_path / "concurrent-buffer.db")
    records = [
        behavior_summary_telemetry(
            TrafficFeatures(index, index + 60, 1, 60, 60, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1.0, 1.0),
            f"EDGE-{index}",
        )
        for index in range(4)
    ]
    for item in records:
        buffer.add(item)
    sender = EdgeSender("http://127.0.0.1:8000", "test-key", max_concurrent_requests=4)
    barrier = threading.Barrier(4)
    failed_record_id = records[1].record_id

    def send(item):
        barrier.wait(timeout=2)
        return item.record_id != failed_record_id

    monkeypatch.setattr(sender, "send_record", send)

    result = sender.send_pending(buffer, limit=4)

    assert result.sent == 3
    assert result.failed == 1
    assert {item.record_id for item in buffer.peek(10)} == {records[1].record_id}


def test_sender_drains_bounded_workload_through_authenticated_hub_concurrently(tmp_path, monkeypatch):
    app = create_app(str(tmp_path / "hub.db"))
    hub = app.state.hub_service
    _, api_key = hub.registry.register("EDGE-LOAD")
    assert hub.registry.authenticate("EDGE-LOAD", api_key)
    client = TestClient(app)
    active_requests = 0
    maximum_active_requests = 0
    active_lock = threading.Lock()

    class ClientResponse(io.BytesIO):
        def __init__(self, status: int, body: bytes):
            super().__init__(body)
            self.status = status

    def hub_post(request, **_kwargs):
        nonlocal active_requests, maximum_active_requests
        with active_lock:
            active_requests += 1
            maximum_active_requests = max(maximum_active_requests, active_requests)
        try:
            response = client.post(
                request.full_url,
                content=request.data,
                headers=dict(request.header_items()),
            )
            return ClientResponse(response.status_code, response.content)
        finally:
            with active_lock:
                active_requests -= 1

    monkeypatch.setattr("rocks.edge.sender.urllib.request.urlopen", hub_post)
    records = generate_records(Scenario.NORMAL, count=128, sensor_id="EDGE-LOAD")
    buffer = TelemetryBuffer(tmp_path / "edge-buffer.db", buffer_limit=128)
    for item in records:
        assert buffer.add(item)
    sender = EdgeSender("http://rocks-test", api_key, max_concurrent_requests=16)

    first = sender.send_pending(buffer, limit=100, sensor_id="EDGE-LOAD")
    second = sender.send_pending(buffer, limit=100, sensor_id="EDGE-LOAD")

    assert (first.sent, first.failed) == (100, 0)
    assert (second.sent, second.failed) == (28, 0)
    assert maximum_active_requests > 1
    assert buffer.size() == 0
    assert buffer.dropped_records == 0
    assert hub.storage.count() == len(records)
