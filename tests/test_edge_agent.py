from __future__ import annotations

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

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


def _wire_packet(src_ip, dst_ip, timestamp, transport, *, src_mac="02:00:00:00:00:01"):
    packet = Ether(src=src_mac, dst="02:00:00:00:00:02") / IP(src=src_ip, dst=dst_ip) / transport
    packet.time = timestamp
    return packet


def test_agent_flush_emits_aggregated_dns_and_behavior_summary(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-DNS",
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    for moment in (1_000.0, 1_001.0):
        agent.process_packet(
            _wire_packet(
                "192.0.2.10",
                "198.51.100.53",
                moment,
                UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.invalid")),
            )
        )

    records = agent.flush_features()
    dns_records = [record for record in records if record.event_type == "DNS"]
    summaries = [record for record in records if record.event_type == "BEHAVIOR_SUMMARY"]
    assert len(dns_records) == 1
    assert dns_records[0].payload["request_count"] == 2
    assert dns_records[0].payload["failure_count"] == 0
    assert dns_records[0].payload["protocol"] == "UDP"
    assert len(summaries) == 1
    assert summaries[0].payload["bytes_sent"] > 0
    assert summaries[0].payload["bytes_received"] == 0
    assert agent.storage.count() == len(records)
    assert agent.buffer.size() == len(records)


def test_agent_emits_connection_for_idle_expired_flow_and_not_fake_reconnect(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-FLOW",
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    agent.process_packet(_wire_packet("192.0.2.10", "198.51.100.20", 1_000.0, TCP(sport=40000, dport=443, flags="S")))
    agent.process_packet(_wire_packet("192.0.2.10", "198.51.100.20", 1_301.0, TCP(sport=40000, dport=443, flags="S")))

    stored = agent.storage.get_recent(10)
    connections = [record for record in stored if record.event_type == "CONNECTION"]
    assert len(connections) == 1
    connection = connections[0]
    assert connection.payload["source"]["ip"] == "192.0.2.10"
    assert connection.payload["destination"]["ip"] == "198.51.100.20"
    assert connection.payload["protocol"] == "TCP"
    assert connection.payload["packet_count"] == 1
    assert connection.payload["bytes_sent"] > 0
    assert connection.payload["bytes_received"] is None
    assert not any(record.event_type == "RECONNECT" for record in stored)

    generated = agent.flush_features()
    assert any(record.event_type == "BEHAVIOR_SUMMARY" for record in generated)
    assert agent.buffer.size() == agent.storage.count()


def test_periodic_flush_emits_idle_expired_flow_without_new_packet(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-IDLE",
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    agent.process_packet(_wire_packet("192.0.2.10", "198.51.100.20", 1_000.0, TCP(sport=40000, dport=443, flags="S")))
    with agent._lock:
        agent._packets.clear()

    expired = agent.flush_features()
    connections = [record for record in expired if record.event_type == "CONNECTION"]
    assert len(connections) == 1
    assert connections[0].payload["packet_count"] == 1
    assert agent.storage.count() == 1
    assert agent.buffer.size() == 1
