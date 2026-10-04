from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, asdict
from typing import Any, Iterable

from rocks.edge.flow import FlowRecord
from rocks.edge.parser import PacketMetadata


@dataclass(frozen=True)
class TrafficFeatures:
    window_start: float
    window_end: float
    packet_count: int
    total_bytes: int
    bytes_sent: int
    bytes_received: int
    connection_count: int
    active_flow_count: int
    unique_destination_ip_count: int
    unique_destination_port_count: int
    unique_source_ip_count: int
    tcp_packet_count: int
    udp_packet_count: int
    icmp_packet_count: int
    dns_packet_count: int
    traffic_rate: float
    packet_rate: float
    device_id: str | None = None
    repeated_destination_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def source_identities(packets: Iterable[PacketMetadata]) -> list[tuple[str, str | None]]:
    """Return unique IPv4 sources and a matching MAC when it is unambiguous."""

    macs_by_ip: dict[str, set[str]] = {}
    order: list[str] = []
    for packet in packets:
        if packet.source_ip is None:
            continue
        if packet.source_ip not in macs_by_ip:
            macs_by_ip[packet.source_ip] = set()
            order.append(packet.source_ip)
        if packet.source_mac:
            macs_by_ip[packet.source_ip].add(packet.source_mac)
    identities: list[tuple[str, str | None]] = []
    for source_ip in order:
        macs = macs_by_ip[source_ip]
        identities.append((source_ip, next(iter(macs)) if len(macs) == 1 else None))
    return identities


def aggregate_features(
    packets: Iterable[PacketMetadata],
    flows: Iterable[FlowRecord] = (),
    *,
    window_start: float | None = None,
    window_end: float | None = None,
    window_seconds: float = 60.0,
    source_ip: str | None = None,
    source_mac: str | None = None,
) -> TrafficFeatures:
    """Aggregate metadata into one configurable time-window feature record.

    When ``source_ip`` is set, the record describes that endpoint:

    - ``bytes_sent``: observed packet lengths where this IP is the IPv4 source
      (traffic from the summarized source toward destinations).
    - ``bytes_received``: observed packet lengths where this IP is the IPv4
      destination (traffic from destinations toward the summarized source).

    Direction is taken only from source/destination IP, never from packet order.
    When ``source_ip`` is omitted, directional byte counters stay 0.
    """

    packet_list = list(packets)
    flow_list = list(flows)
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    scoped_packets = _packets_for_source(packet_list, source_ip)
    scoped_flows = _flows_for_source(flow_list, source_ip)
    outbound = [packet for packet in scoped_packets if source_ip is None or packet.source_ip == source_ip]

    if scoped_packets:
        start = min(packet.timestamp for packet in scoped_packets) if window_start is None else window_start
        end = max(packet.timestamp for packet in scoped_packets) if window_end is None else window_end
    elif packet_list:
        start = min(packet.timestamp for packet in packet_list) if window_start is None else window_start
        end = max(packet.timestamp for packet in packet_list) if window_end is None else window_end
    else:
        start = window_start if window_start is not None else 0.0
        end = window_end if window_end is not None else start + window_seconds

    duration = max(window_seconds, end - start)
    total_bytes = sum(packet.aggregate_bytes or 0 for packet in scoped_packets)
    sent = sum(
        packet.aggregate_bytes or 0
        for packet in scoped_packets
        if source_ip is not None and packet.source_ip == source_ip
    )
    received = sum(
        packet.aggregate_bytes or 0
        for packet in scoped_packets
        if source_ip is not None and packet.destination_ip == source_ip and packet.source_ip != source_ip
    )
    source_macs = {packet.source_mac for packet in outbound if packet.source_mac}
    device_id = None
    if source_ip:
        chosen_mac = source_mac or (next(iter(source_macs)) if len(source_macs) == 1 else "")
        device_id = f"{source_ip}|{chosen_mac}"

    destination_ips = [packet.destination_ip for packet in outbound if packet.destination_ip]
    destination_counts: Counter[str] = Counter()
    for packet in outbound:
        if packet.destination_ip:
            destination_counts[packet.destination_ip] += packet.packet_count

    return TrafficFeatures(
        window_start=start,
        window_end=end,
        packet_count=sum(packet.packet_count for packet in scoped_packets),
        total_bytes=total_bytes,
        bytes_sent=sent,
        bytes_received=received,
        connection_count=len(scoped_flows),
        active_flow_count=len(scoped_flows),
        unique_destination_ip_count=len(set(destination_ips)),
        unique_destination_port_count=len(
            {packet.destination_port for packet in outbound if packet.destination_port is not None}
        ),
        unique_source_ip_count=len({packet.source_ip for packet in scoped_packets if packet.source_ip}),
        tcp_packet_count=sum(packet.packet_count for packet in scoped_packets if packet.protocol == "TCP"),
        udp_packet_count=sum(packet.packet_count for packet in scoped_packets if packet.protocol == "UDP"),
        icmp_packet_count=sum(packet.packet_count for packet in scoped_packets if packet.protocol == "ICMP"),
        dns_packet_count=sum(packet.packet_count for packet in scoped_packets if packet.dns_related),
        traffic_rate=total_bytes / duration,
        packet_rate=sum(packet.packet_count for packet in scoped_packets) / duration,
        device_id=device_id,
        repeated_destination_count=sum(1 for count in destination_counts.values() if count > 1),
    )


def aggregate_features_by_source(
    packets: Iterable[PacketMetadata],
    flows: Iterable[FlowRecord] = (),
    **kwargs: Any,
) -> list[TrafficFeatures]:
    """Build one feature record per observed IPv4 source in the window."""

    packet_list = list(packets)
    flow_list = list(flows)
    return [
        aggregate_features(packet_list, flow_list, source_ip=source_ip, source_mac=source_mac, **kwargs)
        for source_ip, source_mac in source_identities(packet_list)
    ]


def _packets_for_source(packets: list[PacketMetadata], source_ip: str | None) -> list[PacketMetadata]:
    if source_ip is None:
        return packets
    return [
        packet
        for packet in packets
        if packet.source_ip == source_ip or packet.destination_ip == source_ip
    ]


def _flows_for_source(flows: list[FlowRecord], source_ip: str | None) -> list[FlowRecord]:
    if source_ip is None:
        return flows
    return [flow for flow in flows if flow.source_ip == source_ip or flow.destination_ip == source_ip]


class FeatureAggregator:
    """Keep a bounded in-memory packet window for development use."""

    def __init__(self, window_seconds: float = 60.0, max_packets: int = 100_000) -> None:
        if window_seconds <= 0 or max_packets <= 0:
            raise ValueError("window_seconds and max_packets must be greater than zero")
        self.window_seconds = window_seconds
        self.max_packets = max_packets
        self._packets: list[PacketMetadata] = []

    def add(self, packet: PacketMetadata) -> None:
        self._packets.append(packet)
        if len(self._packets) > self.max_packets:
            self._packets.pop(0)

    def features(self, now: float | None = None, **kwargs: Any) -> TrafficFeatures:
        if now is None:
            now = max((packet.timestamp for packet in self._packets), default=0.0)
        start = now - self.window_seconds
        packets = [packet for packet in self._packets if start <= packet.timestamp <= now]
        return aggregate_features(
            packets,
            window_start=start,
            window_end=now,
            window_seconds=self.window_seconds,
            **kwargs,
        )
