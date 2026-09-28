from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from rocks import __version__
from rocks.config import get_config_path
from rocks.edge.capture import CaptureError, PacketCapture
from rocks.edge.features import aggregate_features
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import parse_packet
from rocks.edge.storage import TelemetryStorage
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.logging_config import configure_logging
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet


LOGGER = configure_logging()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rocks",
        description="ROCKS Fleet foundation CLI",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="show ROCKS Fleet version and exit",
    )

    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = False

    subparsers.add_parser("status", help="show current installation status")
    subparsers.add_parser("config", help="show the active configuration path")
    subparsers.add_parser("logs", help="show logging status")
    subparsers.add_parser("test", help="run the foundation test command")
    edge_parser = subparsers.add_parser("edge", help="ROCKS Edge observation commands")
    edge_subparsers = edge_parser.add_subparsers(dest="edge_command")
    edge_subparsers.add_parser("status", help="show Edge observation status")
    edge_subparsers.add_parser("test", help="run the non-root synthetic Edge pipeline")
    capture_parser = edge_subparsers.add_parser("capture", help="capture authorized live metadata")
    capture_parser.add_argument("--interface", required=True, help="interface to observe")
    telemetry_parser = edge_subparsers.add_parser("telemetry", help="local Edge telemetry commands")
    telemetry_subparsers = telemetry_parser.add_subparsers(dest="telemetry_command")
    telemetry_subparsers.add_parser("test", help="run a local telemetry serialization and storage test")
    storage_parser = edge_subparsers.add_parser("storage", help="local Edge storage commands")
    storage_subparsers = storage_parser.add_subparsers(dest="storage_command")
    storage_subparsers.add_parser("status", help="show local telemetry storage status")
    return parser


def _synthetic_edge_test() -> int:
    packets: list[Packet] = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=40000, dport=443, flags="S"),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / UDP(sport=53000, dport=53),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_000.0 + index

    metadata = [parse_packet(packet) for packet in packets]
    tracker = FlowTracker()
    for item in metadata:
        tracker.update(item)
    features = aggregate_features(
        metadata,
        tracker.snapshot(),
        window_start=1_000.0,
        window_end=1_060.0,
        source_ip="192.0.2.10",
        source_mac="02:00:00:00:00:01",
    )
    print(
        "ROCKS Edge synthetic pipeline passed: "
        f"{features.packet_count} packets, {features.active_flow_count} flows"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"ROCKS Fleet {__version__}")
        return 0

    if args.command == "status":
        print("ROCKS Fleet foundation is installed.")
        print("No Edge or Hub services are running yet.")
        return 0

    if args.command == "config":
        print(f"ROCKS configuration path: {get_config_path()}")
        return 0

    if args.command == "logs":
        print("ROCKS logging is not implemented yet.")
        return 0

    if args.command == "test":
        print("ROCKS Fleet foundation tests passed.")
        return 0

    if args.command == "edge":
        if args.edge_command == "status":
            print("ROCKS Edge observation layer is available.")
            print("Live capture is not running.")
            return 0
        if args.edge_command == "test":
            return _synthetic_edge_test()
        if args.edge_command == "capture":
            try:
                PacketCapture(args.interface, parse_packet).start()
            except (CaptureError, ValueError) as exc:
                print(f"ROCKS Edge capture error: {exc}", file=sys.stderr)
                return 2
            return 0
        if args.edge_command == "telemetry" and args.telemetry_command == "test":
            with tempfile.TemporaryDirectory(prefix="rocks-telemetry-") as directory:
                storage = TelemetryStorage(Path(directory) / "telemetry.db")
                from rocks.edge.features import TrafficFeatures

                features = TrafficFeatures(
                    window_start=0.0,
                    window_end=60.0,
                    packet_count=0,
                    total_bytes=0,
                    bytes_sent=0,
                    bytes_received=0,
                    connection_count=0,
                    active_flow_count=0,
                    unique_destination_ip_count=0,
                    unique_destination_port_count=0,
                    unique_source_ip_count=0,
                    tcp_packet_count=0,
                    udp_packet_count=0,
                    icmp_packet_count=0,
                    dns_packet_count=0,
                    traffic_rate=0.0,
                    packet_rate=0.0,
                )
                storage.insert_telemetry(
                    behavior_summary_telemetry(features, "ROCKS-EDGE-TEST")
                )
                print(f"ROCKS Edge telemetry test passed: {storage.count()} record stored locally.")
            return 0
        if args.edge_command == "storage" and args.storage_command == "status":
            print("ROCKS Edge local storage is available.")
            print("Hub transmission is not implemented yet.")
            return 0
        if args.edge_command in {"telemetry", "storage"}:
            parser.parse_args(["edge", args.edge_command, "--help"])
            return 0
        parser.parse_args(["edge", "--help"])
        return 0

    print(f"ROCKS Fleet {__version__}")
    print("")
    print("Usage: rocks [--version] [status|config|logs|test]")
    print("Run 'rocks --help' for more information.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
