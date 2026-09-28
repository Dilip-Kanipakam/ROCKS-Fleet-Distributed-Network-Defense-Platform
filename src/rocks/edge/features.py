from __future__ import annotations

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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    """Aggregate metadata into one configurable time-window feature record."""

    packet_list = list(packets)
    flow_list = list(flows)
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    if packet_list:
        start = min(packet.timestamp for packet in packet_list) if window_start is None else window_start
        end = max(packet.timestamp for packet in packet_list) if window_end is None else window_end
    else:
        start = window_start if window_start is not None else 0.0
        end = window_end if window_end is not None else start + window_seconds

    duration = max(window_seconds, end - start)
    total_bytes = sum(packet.packet_length for packet in packet_list)
    sent = sum(
        packet.packet_length
        for packet in packet_list
        if source_ip is not None and packet.source_ip == source_ip
    )
    received = sum(
        packet.packet_length
        for packet in packet_list
        if source_ip is not None and packet.destination_ip == source_ip
    )
    source_macs = {packet.source_mac for packet in packet_list if packet.source_mac}
    device_id = None
    if source_ip:
        device_id = f"{source_ip}|{source_mac or (next(iter(source_macs)) if len(source_macs) == 1 else '')}"

    return TrafficFeatures(
        window_start=start,
        window_end=end,
        packet_count=len(packet_list),
        total_bytes=total_bytes,
        bytes_sent=sent,
        bytes_received=received,
        connection_count=len(flow_list),
        active_flow_count=len(flow_list),
        unique_destination_ip_count=len({p.destination_ip for p in packet_list if p.destination_ip}),
        unique_destination_port_count=len({p.destination_port for p in packet_list if p.destination_port is not None}),
        unique_source_ip_count=len({p.source_ip for p in packet_list if p.source_ip}),
        tcp_packet_count=sum(p.protocol == "TCP" for p in packet_list),
        udp_packet_count=sum(p.protocol == "UDP" for p in packet_list),
        icmp_packet_count=sum(p.protocol == "ICMP" for p in packet_list),
        dns_packet_count=sum(p.dns_related for p in packet_list),
        traffic_rate=total_bytes / duration,
        packet_rate=len(packet_list) / duration,
        device_id=device_id,
    )


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
