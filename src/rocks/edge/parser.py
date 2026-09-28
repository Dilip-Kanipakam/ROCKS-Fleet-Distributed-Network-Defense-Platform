from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

from scapy.packet import Packet
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether


@dataclass(frozen=True)
class PacketMetadata:
    """Metadata extracted from a packet without retaining payload contents."""

    timestamp: float
    packet_length: int
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str = "OTHER"
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None
    icmp_type: int | None = None
    source_mac: str | None = None
    destination_mac: str | None = None
    dns_related: bool = False

    @property
    def observed_at(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_packet(packet: Packet) -> PacketMetadata:
    """Extract safe, bounded metadata from a Scapy packet."""

    timestamp = float(getattr(packet, "time", 0.0))
    packet_length = len(packet)
    source_mac = packet[Ether].src if packet.haslayer(Ether) else None
    destination_mac = packet[Ether].dst if packet.haslayer(Ether) else None

    if not packet.haslayer(IP):
        return PacketMetadata(
            timestamp=timestamp,
            packet_length=packet_length,
            source_mac=source_mac,
            destination_mac=destination_mac,
        )

    ip_layer = packet[IP]
    common = {
        "timestamp": timestamp,
        "packet_length": packet_length,
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
    }

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        return PacketMetadata(
            **common,
            protocol="TCP",
            source_port=int(tcp_layer.sport),
            destination_port=int(tcp_layer.dport),
            tcp_flags=str(tcp_layer.flags),
            dns_related=int(tcp_layer.sport) == 53 or int(tcp_layer.dport) == 53,
        )

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        return PacketMetadata(
            **common,
            protocol="UDP",
            source_port=int(udp_layer.sport),
            destination_port=int(udp_layer.dport),
            dns_related=(
                int(udp_layer.sport) == 53
                or int(udp_layer.dport) == 53
                or packet.haslayer(DNS)
            ),
        )

    if packet.haslayer(ICMP):
        return PacketMetadata(
            **common,
            protocol="ICMP",
            icmp_type=int(packet[ICMP].type),
        )

    return PacketMetadata(**common, protocol=str(ip_layer.proto))
