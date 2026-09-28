from __future__ import annotations

from pathlib import Path

from rocks.edge.agent import EdgeAgent, EdgeAgentConfig
from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.sender import SendResult
from rocks.simulator.generator import Scenario, generate_records


def test_dry_run_stores_synthetic_telemetry(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-TEST",
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    agent.run_dry_run(generate_records(Scenario.NORMAL, count=2, sensor_id="EDGE-TEST"))
    assert agent.telemetry_generated == 2
    assert agent.storage.count() == 2
    assert agent.buffer.size() == 2
    assert "api_key" not in str(agent.status()).lower()


def test_sender_success_removes_and_failure_preserves(tmp_path, monkeypatch):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-TEST",
            hub_url="http://127.0.0.1:8000",
            api_key="secret-key",
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    records = generate_records(Scenario.NORMAL, count=1, sensor_id="EDGE-TEST")
    agent.run_dry_run(records)
    monkeypatch.setattr(agent.sender, "send_pending", lambda _buffer, limit: SendResult(sent=1, failed=0))
    # A mocked result does not remove data; the real sender contract is tested in test_sender.py.
    assert agent.buffer.size() == 1
    monkeypatch.setattr(agent.sender, "send_pending", lambda _buffer, limit: SendResult(sent=0, failed=1))
    assert agent.send_pending().failed == 1
    assert agent.buffer.size() == 1


def test_missing_interface_fails_before_capture(tmp_path):
    agent = EdgeAgent(EdgeAgentConfig(database_path=tmp_path / "telemetry.db", buffer_path=tmp_path / "buffer.db"))
    try:
        agent.run()
    except ValueError as exc:
        assert "interface" in str(exc).lower()
    else:
        raise AssertionError("expected missing interface failure")
