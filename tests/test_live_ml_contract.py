from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from rocks.edge.agent import EdgeAgent, EdgeAgentConfig
from rocks.edge.features import aggregate_features, aggregate_features_by_source
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import parse_packet
from rocks.edge.telemetry import SCHEMA_VERSION, behavior_summary_telemetry, telemetry_from_json, telemetry_to_json
from rocks.ml.analysis import analyze_behavior_summary
from rocks.ml.features import actual_traffic, behavior_summary_features


def _packet(
    src_ip: str,
    dst_ip: str,
    timestamp: float,
    *,
    src_mac: str = "02:00:00:00:00:01",
    extra_bytes: int = 0,
):
    layer = IP(src=src_ip, dst=dst_ip) / TCP(sport=40000, dport=443)
    if extra_bytes:
        layer = layer / Raw(b"\x00" * extra_bytes)
    result = Ether(src=src_mac, dst="02:00:00:00:00:02") / layer
    result.time = timestamp
    return result


def _metadata(
    src_ip: str,
    dst_ip: str,
    timestamp: float,
    *,
    src_mac: str = "02:00:00:00:00:01",
    extra_bytes: int = 0,
):
    return parse_packet(_packet(src_ip, dst_ip, timestamp, src_mac=src_mac, extra_bytes=extra_bytes))


def test_outbound_only_counts_bytes_sent():
    packets = [_metadata("192.0.2.10", "198.51.100.20", 10.0)]
    features = aggregate_features(packets, source_ip="192.0.2.10")
    assert features.bytes_sent == packets[0].packet_length
    assert features.bytes_sent > 0
    assert features.bytes_received == 0
    assert features.packet_count == 1
    assert features.unique_destination_ip_count == 1
    assert features.device_id == "192.0.2.10|02:00:00:00:00:01"


def test_inbound_only_counts_bytes_received():
    packets = [_metadata("198.51.100.20", "192.0.2.10", 11.0, src_mac="02:00:00:00:00:02")]
    features = aggregate_features(packets, source_ip="192.0.2.10")
    assert features.bytes_received == packets[0].packet_length
    assert features.bytes_received > 0
    assert features.bytes_sent == 0


def test_bidirectional_counts_sent_and_received():
    outbound = _metadata("192.0.2.10", "198.51.100.20", 10.0)
    inbound = _metadata("198.51.100.20", "192.0.2.10", 11.0, src_mac="02:00:00:00:00:02")
    features = aggregate_features([outbound, inbound], source_ip="192.0.2.10")
    assert features.bytes_sent == outbound.packet_length
    assert features.bytes_received == inbound.packet_length
    assert features.bytes_sent > 0
    assert features.bytes_received > 0
    assert features.total_bytes == features.bytes_sent + features.bytes_received


def test_multiple_sources_do_not_mix_byte_counts():
    left = _metadata("192.0.2.10", "198.51.100.20", 10.0, src_mac="02:00:00:00:00:0a", extra_bytes=10)
    right = _metadata("192.0.2.11", "198.51.100.21", 10.0, src_mac="02:00:00:00:00:0b", extra_bytes=40)
    summaries = {item.device_id: item for item in aggregate_features_by_source([left, right])}
    assert summaries["192.0.2.10|02:00:00:00:00:0a"].bytes_sent == left.packet_length
    assert summaries["192.0.2.10|02:00:00:00:00:0a"].bytes_received == 0
    assert summaries["192.0.2.11|02:00:00:00:00:0b"].bytes_sent == right.packet_length
    assert summaries["192.0.2.11|02:00:00:00:00:0b"].bytes_sent != summaries["192.0.2.10|02:00:00:00:00:0a"].bytes_sent
    assert summaries["192.0.2.10|02:00:00:00:00:0a"].bytes_sent != left.packet_length + right.packet_length


def test_repeated_destination_count_from_outbound_packets():
    packets = [
        _metadata("192.0.2.10", "198.51.100.20", 10.0),
        _metadata("192.0.2.10", "198.51.100.20", 11.0),
        _metadata("192.0.2.10", "198.51.100.21", 12.0),
    ]
    features = aggregate_features(packets, source_ip="192.0.2.10")
    assert features.unique_destination_ip_count == 2
    assert features.repeated_destination_count == 1


def test_behavior_summary_schema_and_serialization_remain_valid():
    outbound = _metadata("192.0.2.10", "198.51.100.20", 10.0)
    inbound = _metadata("198.51.100.20", "192.0.2.10", 11.0, src_mac="02:00:00:00:00:02")
    features = aggregate_features([outbound, inbound], source_ip="192.0.2.10")
    record = behavior_summary_telemetry(
        features,
        "ROCKS-EDGE-01",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert record.schema_version == SCHEMA_VERSION
    assert record.event_type == "BEHAVIOR_SUMMARY"
    payload = record.payload
    assert payload["bytes_sent"] == features.bytes_sent
    assert payload["bytes_received"] == features.bytes_received
    assert payload["packet_count"] == features.packet_count
    assert payload["traffic_rate"] == features.traffic_rate
    assert payload["connection_count"] == features.connection_count
    assert payload["active_connections"] == features.active_flow_count
    assert payload["unique_destination_ip_count"] == features.unique_destination_ip_count
    assert payload["repeated_destination_count"] == features.repeated_destination_count
    assert payload["dns_failure_count"] == 0
    assert payload["reconnect_count"] == 0
    assert payload["connection_failure_count"] == 0
    assert telemetry_from_json(telemetry_to_json(record)) == record


def test_live_packet_path_to_ml_features_and_analysis():
    outbound = parse_packet(_packet("192.0.2.10", "198.51.100.20", 1_000.0, extra_bytes=10))
    inbound = parse_packet(_packet("198.51.100.20", "192.0.2.10", 1_001.0, src_mac="02:00:00:00:00:02", extra_bytes=20))
    tracker = FlowTracker()
    tracker.update(outbound)
    tracker.update(inbound)
    features = aggregate_features(
        [outbound, inbound],
        tracker.snapshot(),
        window_seconds=60.0,
        source_ip="192.0.2.10",
        source_mac="02:00:00:00:00:01",
    )
    record = behavior_summary_telemetry(features, "ROCKS-EDGE-LIVE", timestamp=datetime(2026, 1, 5, 9, tzinfo=timezone.utc))
    ml_features = behavior_summary_features(record)
    traffic = actual_traffic(record)
    assert features.bytes_sent > 0
    assert features.bytes_received > 0
    assert traffic == features.bytes_sent + features.bytes_received
    assert traffic > 0
    assert ml_features["bytes_sent"] == features.bytes_sent
    assert ml_features["bytes_received"] == features.bytes_received
    result = analyze_behavior_summary(
        record,
        expected_traffic=float(traffic),
        baseline_status="READY",
        analyzed_at="2026-01-05T09:00:00Z",
    )
    assert result.actual_traffic == traffic
    assert result.anomaly_score is not None
    assert 0.0 <= result.anomaly_score <= 1.0


def test_agent_flush_emits_per_source_directional_summaries(tmp_path: Path):
    agent = EdgeAgent(
        EdgeAgentConfig(
            sensor_id="EDGE-LIVE",
            database_path=tmp_path / "telemetry.db",
            buffer_path=tmp_path / "buffer.db",
        )
    )
    agent.process_packet(_packet("192.0.2.10", "198.51.100.20", 10.0, src_mac="02:00:00:00:00:0a", extra_bytes=10))
    agent.process_packet(_packet("198.51.100.20", "192.0.2.10", 11.0, src_mac="02:00:00:00:00:02", extra_bytes=20))
    agent.process_packet(_packet("192.0.2.11", "198.51.100.21", 12.0, src_mac="02:00:00:00:00:0b", extra_bytes=40))
    records = agent.flush_features()
    by_device = {record.device_id: record for record in records}
    left = by_device["192.0.2.10|02:00:00:00:00:0a"]
    right = by_device["192.0.2.11|02:00:00:00:00:0b"]
    assert left.payload["bytes_sent"] > 0
    assert left.payload["bytes_received"] > 0
    assert right.payload["bytes_sent"] > 0
    assert right.payload["bytes_received"] == 0
    assert left.payload["bytes_sent"] != right.payload["bytes_sent"]
    assert agent.storage.count() == len(records)
    assert agent.buffer.size() == len(records)
    assert "payload" not in str(left.payload).lower()
