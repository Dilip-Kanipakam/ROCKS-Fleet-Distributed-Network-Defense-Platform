from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from rocks.edge.capture import CaptureError, PacketCapture
from rocks.edge.features import FeatureAggregator, aggregate_features
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import parse_packet


def packet(layer, timestamp: float, *, source_mac: str = "02:00:00:00:00:01"):
    result = Ether(src=source_mac, dst="02:00:00:00:00:02") / layer
    result.time = timestamp
    return result


def test_ipv4_tcp_and_ethernet_metadata():
    metadata = parse_packet(
        packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1234, dport=443, flags="S"), 10.0)
    )
    assert metadata.source_ip == "192.0.2.1"
    assert metadata.destination_ip == "198.51.100.1"
    assert metadata.protocol == "TCP"
    assert metadata.source_port == 1234
    assert metadata.destination_port == 443
    assert metadata.tcp_flags == "S"
    assert metadata.source_mac == "02:00:00:00:00:01"
    assert metadata.destination_mac == "02:00:00:00:00:02"


def test_udp_and_dns_metadata():
    metadata = parse_packet(
        packet(IP(src="192.0.2.1", dst="198.51.100.53") / UDP(sport=53000, dport=53), 10.0)
    )
    assert metadata.protocol == "UDP"
    assert metadata.source_port == 53000
    assert metadata.destination_port == 53
    assert metadata.dns_related is True


def test_icmp_metadata():
    metadata = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / ICMP(type=8), 10.0))
    assert metadata.protocol == "ICMP"
    assert metadata.icmp_type == 8


def test_missing_layer_packet_is_safe():
    metadata = parse_packet(packet(Raw(b"not retained"), 10.0))
    assert metadata.protocol == "OTHER"
    assert metadata.source_ip is None
    assert metadata.destination_ip is None


def test_invalid_capture_interface_has_clear_error():
    capture = PacketCapture("__rocks_missing_interface__", lambda _packet: None)
    try:
        capture.validate_interface()
    except CaptureError as exc:
        assert "does not exist" in str(exc)
    else:
        raise AssertionError("expected an invalid interface error")


def test_flow_creation_and_byte_packet_counting():
    tracker = FlowTracker()
    first = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1234, dport=443), 10.0))
    second = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1234, dport=443), 12.0))
    record = tracker.update(first)
    tracker.update(second)
    assert record is not None
    assert tracker.active_flow_count == 1
    assert tracker.snapshot()[0].packet_count == 2
    assert tracker.snapshot()[0].bytes == first.packet_length + second.packet_length
    assert tracker.snapshot()[0].duration == 2.0
    assert tracker.snapshot()[0].packets_per_second == 1.0


def test_reverse_direction_packets_share_one_flow():
    tracker = FlowTracker(expiration_seconds=5.0)
    outbound = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1234, dport=443), 10.0))
    inbound = parse_packet(packet(IP(src="198.51.100.1", dst="192.0.2.1") / TCP(sport=443, dport=1234), 11.0))

    first = tracker.update(outbound)
    reverse = tracker.update(inbound)

    assert first is reverse
    assert tracker.active_flow_count == 1
    assert reverse is not None
    assert reverse.packet_count == 2
    assert reverse.bytes == outbound.packet_length
    assert reverse.reverse_packet_count == 1
    assert reverse.reverse_bytes == inbound.packet_length
    assert len(tracker.expire(16.0)) == 1


def test_multiple_flows_and_protocol_without_ports():
    tracker = FlowTracker()
    tcp = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1, dport=2), 10.0))
    udp = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=3, dport=4), 10.0))
    icmp = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.3") / ICMP(), 10.0))
    for metadata in (tcp, udp, icmp):
        tracker.update(metadata)
    assert tracker.active_flow_count == 3
    assert {(flow.protocol, flow.source_port, flow.destination_port) for flow in tracker.snapshot()} == {
        ("TCP", 1, 2),
        ("UDP", 3, 4),
        ("ICMP", 0, 0),
    }


def test_flow_expiration():
    tracker = FlowTracker(expiration_seconds=5.0)
    metadata = parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=1, dport=2), 10.0))
    tracker.update(metadata)
    expired = tracker.expire(15.0)
    assert len(expired) == 1
    assert tracker.active_flow_count == 0


def test_feature_aggregation_and_rates():
    packets = [
        parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1000, dport=443), 100.0)),
        parse_packet(packet(IP(src="198.51.100.1", dst="192.0.2.1") / UDP(sport=53, dport=1001), 101.0)),
        parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.2") / ICMP(), 102.0)),
    ]
    tracker = FlowTracker()
    for metadata in packets:
        tracker.update(metadata)
    features = aggregate_features(
        packets,
        tracker.snapshot(),
        window_start=100.0,
        window_end=160.0,
        source_ip="192.0.2.1",
        source_mac="02:00:00:00:00:01",
    )
    assert features.packet_count == 3
    assert features.total_bytes == sum(item.packet_length for item in packets)
    assert features.bytes_sent == packets[0].packet_length + packets[2].packet_length
    assert features.bytes_received == packets[1].packet_length
    assert features.connection_count == 3
    assert features.active_flow_count == 3
    assert features.unique_destination_ip_count == 2
    assert features.unique_destination_port_count == 1
    assert features.repeated_destination_count == 0
    assert features.unique_source_ip_count == 2
    assert features.tcp_packet_count == 1
    assert features.udp_packet_count == 1
    assert features.icmp_packet_count == 1
    assert features.dns_packet_count == 1
    assert features.packet_rate == 3 / 60
    assert features.traffic_rate == features.total_bytes / 60
    assert features.device_id == "192.0.2.1|02:00:00:00:00:01"
    assert features.total_bytes == features.bytes_sent + features.bytes_received


def test_feature_aggregator_window():
    aggregator = FeatureAggregator(window_seconds=60.0)
    aggregator.add(parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(), 100.0)))
    aggregator.add(parse_packet(packet(IP(src="192.0.2.1", dst="198.51.100.2") / TCP(), 20.0)))
    features = aggregator.features(now=100.0)
    assert features.packet_count == 1
    assert features.window_start == 40.0
    assert features.window_end == 100.0
