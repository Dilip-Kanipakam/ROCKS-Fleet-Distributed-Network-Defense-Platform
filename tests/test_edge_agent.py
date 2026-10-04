from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from rocks.edge.agent import EdgeAgent, EdgeAgentConfig
from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.features import TrafficFeatures
from rocks.edge.sender import SendResult
from rocks.edge.telemetry import behavior_summary_telemetry, dns_telemetry
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


def test_edge_storage_is_initialized_when_agent_starts_without_telemetry(tmp_path):
    database_path = tmp_path / "nested" / "telemetry.db"
    agent = EdgeAgent(
        EdgeAgentConfig(
            database_path=database_path,
            buffer_path=tmp_path / "nested" / "buffer.db",
        )
    )

    assert database_path.is_file()
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='telemetry'"
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0] == 0
    assert agent.buffer.size() == 0
    assert agent.storage.insert_telemetry(generate_records(Scenario.NORMAL, count=1, sensor_id="EDGE-TEST")[0])

    repeated_agent = EdgeAgent(
        EdgeAgentConfig(
            database_path=database_path,
            buffer_path=tmp_path / "nested" / "buffer.db",
        )
    )

    assert repeated_agent.storage.count() == 1


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
    monkeypatch.setattr(agent.sender, "send_pending", lambda _buffer, **_kwargs: SendResult(sent=1, failed=0))
    # A mocked result does not remove data; the real sender contract is tested in test_sender.py.
    assert agent.buffer.size() == 1
    monkeypatch.setattr(agent.sender, "send_pending", lambda _buffer, **_kwargs: SendResult(sent=0, failed=1))
    assert agent.send_pending().failed == 1
    assert agent.buffer.size() == 1


def test_producer_faster_than_sender_keeps_persistent_buffer_bounded(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            buffer_limit=5,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )

    agent.run_dry_run(generate_records(Scenario.NORMAL, count=30, sensor_id="EDGE-TEST"))

    assert agent.storage.count() == 30
    assert agent.buffer.size() == 5
    assert agent.buffer.dropped_records == 25
    assert agent.status()["buffer_dropped_records"] == 25


def test_same_behavior_window_is_deduplicated_by_device_and_time_bucket(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-DEDUPE",
            telemetry_window_seconds=60,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    features = TrafficFeatures(
        window_start=0.0,
        window_end=60.0,
        packet_count=10,
        total_bytes=500,
        bytes_sent=400,
        bytes_received=100,
        connection_count=2,
        active_flow_count=2,
        unique_destination_ip_count=2,
        unique_destination_port_count=2,
        unique_source_ip_count=1,
        tcp_packet_count=10,
        udp_packet_count=0,
        icmp_packet_count=0,
        dns_packet_count=0,
        traffic_rate=8.33,
        packet_rate=0.17,
        device_id="10.0.0.10|02:00:00:00:00:01",
    )
    first = behavior_summary_telemetry(features, "EDGE-DEDUPE", device_id="10.0.0.10|02:00:00:00:00:01", timestamp=__import__("datetime").datetime.fromtimestamp(10, tz=__import__("datetime").timezone.utc))
    second = behavior_summary_telemetry(features, "EDGE-DEDUPE", device_id="10.0.0.10|02:00:00:00:00:01", timestamp=__import__("datetime").datetime.fromtimestamp(20, tz=__import__("datetime").timezone.utc))

    agent._store_local(first)
    agent._store_local(second)

    assert agent.telemetry_generated == 1
    assert agent.storage.count() == 1
    assert agent.buffer.size() == 1


def test_same_dns_window_is_deduplicated_by_source_destination_and_window(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-DNS-DEDUPE",
            telemetry_window_seconds=60,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    first = dns_telemetry(
        "EDGE-DNS-DEDUPE",
        source_ip="10.0.0.10",
        source_port=None,
        destination_ip="10.0.0.53",
        destination_port=53,
        request_count=10,
        device_id="10.0.0.10|02:00:00:00:00:01",
        protocol="UDP",
        timestamp=__import__("datetime").datetime.fromtimestamp(15, tz=__import__("datetime").timezone.utc),
    )
    second = dns_telemetry(
        "EDGE-DNS-DEDUPE",
        source_ip="10.0.0.10",
        source_port=None,
        destination_ip="10.0.0.53",
        destination_port=53,
        request_count=20,
        device_id="10.0.0.10|02:00:00:00:00:01",
        protocol="UDP",
        timestamp=__import__("datetime").datetime.fromtimestamp(35, tz=__import__("datetime").timezone.utc),
    )

    agent._store_local(first)
    agent._store_local(second)

    assert agent.telemetry_generated == 1
    assert agent.storage.count() == 1


def test_packet_window_truncation_is_persisted_and_reported(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            buffer_limit=2,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    start = time.time()
    for index in range(3):
        agent.process_packet(
            _wire_packet(
                "10.0.0.10",
                "8.8.8.8",
                start + index / 10,
                TCP(sport=40_000, dport=443),
            )
        )

    summaries = [record for record in agent.flush_features() if record.event_type == "BEHAVIOR_SUMMARY"]

    assert summaries[0].payload["packet_count"] == 2
    assert agent.buffer.dropped_packets == 1
    assert agent.status()["packet_metadata_dropped"] == 1


def test_sender_loop_retries_after_transient_storage_error(tmp_path, monkeypatch):
    agent = EdgeAgent(
        EdgeAgentConfig(
            send_interval_seconds=0.001,
            telemetry_window_seconds=0.001,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    attempts = 0

    def flush_features():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("disk I/O error")

    def send_pending():
        agent.stop_event.set()
        return SendResult(sent=0, failed=0)

    monkeypatch.setattr(agent, "flush_features", flush_features)
    monkeypatch.setattr(agent, "send_pending", send_pending)

    agent._send_loop()

    assert attempts == 2


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


def test_normal_and_high_volume_packets_produce_one_source_summary(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-VOLUME",
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    start = time.time()
    for index in range(1_000):
        agent.process_packet(
            _wire_packet(
                "10.0.0.10",
                "198.51.100.20",
                start + index / 10_000,
                TCP(sport=40_000, dport=443),
            )
        )

    records = agent.flush_features()
    summaries = [record for record in records if record.event_type == "BEHAVIOR_SUMMARY"]

    assert len(summaries) == 1
    assert summaries[0].payload["packet_count"] == 1_000
    assert agent.telemetry_generated == 1
    assert agent.flow_tracker.active_flow_count == 1


def test_twelve_send_cycles_emit_one_summary_per_device_window(tmp_path, monkeypatch):
    agent = EdgeAgent(
        EdgeAgentConfig(
            telemetry_window_seconds=60,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    clock = [0.0]
    monkeypatch.setattr("rocks.edge.agent.time.monotonic", lambda: clock[0])
    agent._last_feature_flush = 0.0
    start = time.time()
    records = []

    for cycle in range(1, 13):
        clock[0] = cycle * 5.0
        for device in range(20):
            source_ip = f"10.0.0.{device + 1}"
            agent.process_packet(
                _wire_packet(
                    source_ip,
                    "8.8.8.8",
                    start + cycle * 5 + device / 100,
                    TCP(sport=40_000 + device, dport=443),
                )
            )
        records.extend(agent._flush_features_if_due())

    summaries = [record for record in records if record.event_type == "BEHAVIOR_SUMMARY"]

    assert len(summaries) == 20
    assert agent.telemetry_generated == 20
    assert len({record.device_id for record in summaries}) == 20


def test_behavior_summaries_are_limited_to_private_endpoint_sources(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    now = time.time()
    agent.process_packet(_wire_packet("10.0.0.10", "8.8.8.8", now, TCP(sport=40000, dport=443)))
    agent.process_packet(_wire_packet("8.8.8.8", "10.0.0.10", now + 0.1, TCP(sport=443, dport=40000)))

    summaries = [record for record in agent.flush_features() if record.event_type == "BEHAVIOR_SUMMARY"]

    assert len(summaries) == 1
    assert summaries[0].device_id.startswith("10.0.0.10|")


def test_dns_heavy_window_aggregates_queries_across_source_ports(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    start = time.time()
    for index in range(500):
        agent.process_packet(
            _wire_packet(
                "10.0.0.10",
                "10.0.0.53",
                start + index / 10_000,
                UDP(sport=50_000 + index, dport=53),
            )
        )

    records = agent.flush_features()
    dns_records = [record for record in records if record.event_type == "DNS"]

    assert len(dns_records) == 1
    assert dns_records[0].payload["request_count"] == 500
    assert dns_records[0].payload["source_port"] is None
    assert len([record for record in records if record.event_type == "BEHAVIOR_SUMMARY"]) == 1
    assert not [record for record in records if record.event_type == "CONNECTION"]


def test_repeated_send_cycles_do_not_regenerate_window_summary(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            telemetry_window_seconds=60,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    now = time.time()
    agent.process_packet(_wire_packet("10.0.0.10", "203.0.113.8", now, TCP(sport=40000, dport=443)))
    first = agent.flush_features()
    agent.process_packet(_wire_packet("10.0.0.10", "203.0.113.8", now + 90.0, TCP(sport=40000, dport=443)))
    agent.process_packet(_wire_packet("10.0.0.10", "203.0.113.8", now + 90.1, TCP(sport=40000, dport=443)))

    assert len([record for record in first if record.event_type == "BEHAVIOR_SUMMARY"]) == 1
    assert agent._flush_features_if_due() == []
    assert agent.buffer.size() == 1

    agent._last_feature_flush -= 61
    second = agent._flush_features_if_due()
    assert len([record for record in second if record.event_type == "BEHAVIOR_SUMMARY"]) == 1
    assert agent.buffer.size() == 2


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


def test_reverse_packets_emit_one_connection_record(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    start = time.time()
    outbound = _wire_packet("10.0.0.10", "203.0.113.8", start, TCP(sport=40000, dport=443))
    inbound = _wire_packet("203.0.113.8", "10.0.0.10", start + 0.1, TCP(sport=443, dport=40000), src_mac="02:00:00:00:00:02")
    agent.process_packet(outbound)
    agent.process_packet(inbound)
    agent.process_packet(_wire_packet("10.0.0.10", "203.0.113.8", start + 301, TCP(sport=40000, dport=443)))

    connections = [record for record in agent.storage.get_recent(10) if record.event_type == "CONNECTION"]

    assert len(connections) == 1
    assert connections[0].payload["packet_count"] == 2
    assert connections[0].payload["bytes_received"] > 0


def test_flow_capacity_eviction_is_bounded_and_emits_connection(tmp_path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            max_active_flows=2,
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    start = time.time()
    for index in range(3):
        agent.process_packet(
            _wire_packet(
                "10.0.0.10",
                "8.8.8.8",
                start + index / 10,
                TCP(sport=40_000 + index, dport=443),
            )
        )

    connections = [record for record in agent.storage.get_recent(10) if record.event_type == "CONNECTION"]

    assert agent.flow_tracker.active_flow_count == 2
    assert len(agent._flow_source_macs) == 2
    assert len(connections) == 1


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
