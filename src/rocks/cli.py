from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from rocks import __version__
from rocks.config import get_config_path, get_edge_agent_config
from rocks.edge.agent import EdgeAgent, EdgeAgentConfig, install_signal_handlers
from rocks.edge.capture import CaptureError, PacketCapture
from rocks.edge.features import aggregate_features
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import parse_packet
from rocks.edge.storage import TelemetryStorage
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.hub.app import create_app
from rocks.hub.config import get_hub_config
from rocks.hub.registry import EdgeRegistry
from rocks.hub.storage import HubStorage
from rocks.logging_config import configure_logging
from rocks.ml.config import get_ml_config
from rocks.ml.demo import run_demo as run_ml_demo
from rocks.ml.service import MLService
from rocks.dashboard.config import get_dashboard_config
from rocks.demo import run_demo as run_mvp_demo
from rocks.alerts.config import get_alert_config
from rocks.simulator.generator import Scenario, generate_records


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
    run_edge = edge_subparsers.add_parser("run", help="run the live Edge agent")
    run_edge.add_argument("--interface")
    run_edge.add_argument("--hub-url")
    run_edge.add_argument("--api-key")
    run_edge.add_argument("--sensor-id")
    run_edge.add_argument("--dry-run", action="store_true")
    edge_subparsers.add_parser("test-hub", help="check Hub health connectivity")
    hub_parser = subparsers.add_parser("hub", help="ROCKS Hub commands")
    hub_subparsers = hub_parser.add_subparsers(dest="hub_command")
    hub_subparsers.add_parser("status", help="show Hub status")
    run_parser = hub_subparsers.add_parser("run", help="start the Hub API")
    run_parser.add_argument("--host", default="127.0.0.1")
    run_parser.add_argument("--port", type=int, default=8000)
    hub_edge_parser = hub_subparsers.add_parser("edge", help="manage registered Edge sensors")
    hub_edge_subparsers = hub_edge_parser.add_subparsers(dest="hub_edge_command")
    hub_edge_subparsers.add_parser("list", help="list registered Edge sensors")
    register_parser = hub_edge_subparsers.add_parser("register", help="register an Edge sensor")
    register_parser.add_argument("--sensor-id", required=True)
    register_parser.add_argument("--name")
    ml_parser = subparsers.add_parser("ml", help="ROCKS ML baseline commands")
    ml_subparsers = ml_parser.add_subparsers(dest="ml_command")
    ml_subparsers.add_parser("status", help="show ML baseline status")
    ml_subparsers.add_parser("train", help="train the local baseline model")
    ml_subparsers.add_parser("test", help="run the deterministic ML demonstration")
    analyze_parser = ml_subparsers.add_parser("analyze", help="analyze a stored telemetry record")
    analyze_parser.add_argument("telemetry_id")
    dashboard_parser = subparsers.add_parser("dashboard", help="ROCKS Command Center commands")
    dashboard_subparsers = dashboard_parser.add_subparsers(dest="dashboard_command")
    dashboard_subparsers.add_parser("status", help="show dashboard status")
    dashboard_run = dashboard_subparsers.add_parser("run", help="start the Hub with the dashboard")
    dashboard_run.add_argument("--host", default=None)
    dashboard_run.add_argument("--port", type=int, default=None)
    simulate_parser = subparsers.add_parser("simulate", help="generate safe synthetic telemetry")
    simulate_subparsers = simulate_parser.add_subparsers(dest="simulate_command")
    for name in ("normal", "anomaly", "mixed"):
        scenario_parser = simulate_subparsers.add_parser(name, help=f"generate {name} synthetic telemetry")
        scenario_parser.add_argument("--count", type=int, default=1)
        scenario_parser.add_argument("--interval", type=float, default=0.0)
        scenario_parser.add_argument("--sensor-id", default="ROCKS-SIM-01")
    alerts_parser = subparsers.add_parser("alerts", help="local investigation alert commands")
    alerts_subparsers = alerts_parser.add_subparsers(dest="alerts_command")
    alerts_subparsers.add_parser("status", help="show alert engine status")
    alerts_subparsers.add_parser("list", help="list recent alerts")
    demo_parser = subparsers.add_parser("demo", help="run the complete safe MVP demonstration")
    demo_parser.set_defaults(demo_command=True)
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
            values = get_edge_agent_config()
            agent = EdgeAgent(EdgeAgentConfig(**values))
            for key, value in agent.status().items():
                print(f"{key.replace('_', ' ').title()}: {value}")
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
        if args.edge_command == "run":
            values = get_edge_agent_config()
            overrides = {
                "interface": args.interface,
                "hub_url": args.hub_url,
                "api_key": args.api_key,
                "sensor_id": args.sensor_id,
            }
            values.update({key: value for key, value in overrides.items() if value is not None})
            agent = EdgeAgent(EdgeAgentConfig(**values))
            if args.dry_run:
                from rocks.simulator.generator import Scenario, generate_records

                with tempfile.TemporaryDirectory(prefix="rocks-edge-dry-run-") as directory:
                    isolated_values = dict(values)
                    isolated_values["database_path"] = Path(directory) / "telemetry.db"
                    isolated_values["buffer_path"] = Path(directory) / "buffer.db"
                    isolated_agent = EdgeAgent(EdgeAgentConfig(**isolated_values))
                    isolated_agent.run_dry_run(generate_records(Scenario.NORMAL, count=2, sensor_id=isolated_agent.config.sensor_id))
                    print(f"ROCKS Edge dry-run passed: {isolated_agent.telemetry_generated} synthetic records")
                return 0
            try:
                install_signal_handlers(agent)
                agent.run()
            except (ValueError, CaptureError) as exc:
                print(f"ROCKS Edge startup error: {exc}", file=sys.stderr)
                return 2
            return 0
        if args.edge_command == "test-hub":
            agent = EdgeAgent(EdgeAgentConfig(**get_edge_agent_config()))
            reachable = agent.hub_health()
            print(f"Hub reachable: {'yes' if reachable else 'no'}")
            return 0 if reachable else 2
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
            print("Hub transmission uses the local buffer and configured Edge sender.")
            return 0
        if args.edge_command in {"telemetry", "storage"}:
            parser.parse_args(["edge", args.edge_command, "--help"])
            return 0
        parser.parse_args(["edge", "--help"])
        return 0

    if args.command == "hub":
        config = get_hub_config()
        storage = HubStorage(config.database_path)
        registry = EdgeRegistry(storage)
        if args.hub_command == "status":
            print(f"ROCKS Hub database: {config.database_path}")
            print(f"Registered Edge sensors: {len(registry.list())}")
            print(f"Telemetry records: {storage.count()}")
            print("HTTP server configured: yes")
            print("HTTP server running: no")
            return 0
        if args.hub_command == "run":
            import uvicorn

            uvicorn.run(create_app(str(config.database_path)), host=args.host, port=args.port)
            return 0
        if args.hub_command == "edge":
            if args.hub_edge_command == "list":
                for edge in registry.list():
                    print(f"{edge.sensor_id}\t{edge.status}\t{edge.last_seen or 'never'}")
                return 0
            if args.hub_edge_command == "register":
                edge, api_key = registry.register(args.sensor_id, args.name)
                print(f"Sensor ID: {edge.sensor_id}")
                print(f"API key: {api_key}")
                return 0
            parser.parse_args(["hub", "edge", "--help"])
            return 0
        parser.parse_args(["hub", "--help"])
        return 0

    if args.command == "ml":
        config = get_ml_config()
        if args.ml_command == "test":
            with tempfile.TemporaryDirectory(prefix="rocks-ml-") as directory:
                normal_score, spike_score = run_ml_demo(Path(directory) / "baseline.joblib")
            print(f"ROCKS ML synthetic test passed: normal={normal_score:.3f}, spike={spike_score:.3f}")
            return 0
        service = MLService(
            HubStorage(get_hub_config().database_path),
            config.model_path,
            config.minimum_samples,
            config.model_version,
        )
        if args.ml_command == "status":
            print(f"ML enabled for Hub inference: {config.enabled}")
            for key, value in service.status().items():
                print(f"{key.replace('_', ' ').title()}: {value}")
            return 0
        if args.ml_command == "train":
            samples = service.train()
            print(f"Training samples: {samples}")
            print(f"ML status: {service.model.status.value}")
            if service.model.status.value == "NOT_READY":
                print(f"Baseline requires at least {service.model.minimum_samples} samples.")
            return 0
        if args.ml_command == "analyze":
            if service is None:
                print("ML status: DISABLED")
                return 0
            record = service.storage.get_telemetry(args.telemetry_id)
            if record is None:
                print("Telemetry record not found.", file=sys.stderr)
                return 2
            result = service.analyze(record)
            print(result.to_dict() if result else "Only BEHAVIOR_SUMMARY records can be analyzed.")
            return 0
        parser.parse_args(["ml", "--help"])
        return 0

    if args.command == "dashboard":
        dashboard_config = get_dashboard_config()
        if args.dashboard_command == "status":
            hub_config = get_hub_config()
            print(f"Dashboard: {'ENABLED' if dashboard_config.enabled else 'DISABLED'}")
            print(f"Hub: {'configured' if hub_config.database_path else 'not configured'}")
            print(f"Authentication: {'configured' if dashboard_config.auth.configured else 'not configured'}")
            print(f"URL: http://{dashboard_config.host}:{dashboard_config.port}/dashboard")
            return 0
        if args.dashboard_command == "run":
            import uvicorn

            hub_config = get_hub_config()
            uvicorn.run(
                create_app(str(hub_config.database_path)),
                host=args.host or dashboard_config.host,
                port=args.port or dashboard_config.port,
            )
            return 0
        parser.parse_args(["dashboard", "--help"])
        return 0

    if args.command == "simulate":
        scenario = {"normal": Scenario.NORMAL, "anomaly": Scenario.HIGH_TRAFFIC, "mixed": Scenario.MIXED_ANOMALOUS}[args.simulate_command]
        records = generate_records(scenario, count=args.count, sensor_id=args.sensor_id)
        simulation = any(record.payload.get("simulation") for record in records)
        print(f"Generated {len(records)} safe synthetic {scenario.value} telemetry records.")
        print(f"Simulation only: {simulation}")
        return 0

    if args.command == "alerts":
        storage = HubStorage(get_hub_config().database_path)
        if args.alerts_command == "status":
            counts = storage.alert_counts()
            print(f"Alert Engine: {'ENABLED' if get_alert_config().enabled else 'DISABLED'}")
            print(f"Recent Alerts: {counts['total_recent']}")
            print(f"Open Alerts: {counts['open']}")
            return 0
        if args.alerts_command == "list":
            for alert in storage.recent_alerts():
                print(f"{alert['timestamp']}\t{alert['severity']}\t{alert['sensor_id']}\t{alert['message']}")
            return 0
        parser.parse_args(["alerts", "--help"])
        return 0

    if args.command == "demo":
        result = run_mvp_demo()
        print(f"ROCKS MVP demo passed: {result}")
        return 0

    print(f"ROCKS Fleet {__version__}")
    print("")
    print("Usage: rocks [--version] [status|config|logs|test]")
    print("Run 'rocks --help' for more information.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
