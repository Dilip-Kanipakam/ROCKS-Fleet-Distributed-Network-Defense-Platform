from __future__ import annotations

import argparse
import getpass
import json
import math
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from rocks import __version__
from rocks.config import (
    DEFAULT_CONFIG_TEMPLATE_PATH,
    build_default_config,
    get_config_path,
    get_edge_agent_config,
    load_config,
    validate_positive_integer,
    write_config,
)
from rocks.dashboard.auth import hash_password
from rocks.edge.agent import EdgeAgent, EdgeAgentConfig, install_signal_handlers
from rocks.edge.capture import CaptureError, PacketCapture
from rocks.edge.features import aggregate_features
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import parse_packet
from rocks.edge.storage import TelemetryStorage
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.hub.app import create_app
from rocks.hub.auth import hash_api_key
from rocks.hub.config import get_hub_config
from rocks.hub.registry import EdgeRegistry
from rocks.hub.storage import HubStorage
from rocks.hub.investigation import validate_case_text, validate_identifier, validate_investigation_id
from rocks.logging_config import configure_logging
from rocks.ml.config import get_ml_config
from rocks.ml.demo import run_demo as run_ml_demo
from rocks.ml.service import MLService
from rocks.dashboard.config import get_dashboard_config
from rocks.paths import data_dir
from rocks.demo import DemoMode, normalize_demo_mode, normalize_demo_scenario, run_demo as run_mvp_demo, run_demo_sequence
from rocks.alerts.config import get_alert_config
from rocks.alerts.config import get_email_config
from rocks.alerts.email import EmailNotificationService, NotificationError
from rocks.simulator.generator import Scenario, generate_records
from rocks.service_manager import ServiceManager, ServiceManagerError
from rocks.health import HealthChecker, HealthStatus
from rocks.detection.config import get_detection_config
from rocks.detection.engine import DetectionEngine
from rocks.installer import (
    dashboard_url,
    detect_platform,
    listener_port_available,
    physical_interfaces,
    python_version_supported,
    service_base_url,
    service_install_command,
)


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
    subparsers.add_parser("version", help="show ROCKS Fleet version (alias for --version)")
    subparsers.add_parser("config", help="show the active configuration path")
    subparsers.add_parser("logs", help="show logging status")
    subparsers.add_parser("test", help="run the foundation test command")
    health_parser = subparsers.add_parser("health", help="check ROCKS Fleet runtime health")
    health_parser.add_argument("view", nargs="?", choices=["check", "verbose"], default="check")
    detection_parser = subparsers.add_parser("detection", help="inspect deterministic detection rules")
    detection_subparsers = detection_parser.add_subparsers(dest="detection_command")
    detection_subparsers.add_parser("status", help="show deterministic detection configuration")
    detection_subparsers.add_parser("test", help="evaluate synthetic examples without network traffic")
    service_parser = subparsers.add_parser("service", help="manage ROCKS Linux systemd services")
    service_subparsers = service_parser.add_subparsers(dest="service_command")
    service_subparsers.add_parser("status", help="show installed and running service state")
    service_subparsers.add_parser("verify", help="verify running service state and security settings")
    service_subparsers.add_parser("install", help="install and start services for the configured mode")
    service_subparsers.add_parser("uninstall", help="stop, disable, and remove ROCKS service units")
    service_subparsers.add_parser("start", help="start configured ROCKS services")
    service_subparsers.add_parser("stop", help="stop configured ROCKS services")
    service_subparsers.add_parser("restart", help="restart configured ROCKS services")
    generate_service_parser = service_subparsers.add_parser(
        "generate", help="write unit files to a directory without installing them"
    )
    generate_service_parser.add_argument("--output-dir", required=True)
    install_parser = subparsers.add_parser("install", help="install ROCKS and guide first-time setup")
    install_parser.add_argument("--mode", help="deployment mode: edge, hub, or all-in-one")
    install_parser.add_argument("--config-path", help="path to the YAML config file to create or update")
    install_parser.add_argument("--force", action="store_true", help="overwrite an existing config file when running installation setup")
    install_parser.add_argument("--non-interactive", action="store_true", help="reuse and validate an existing configuration without prompts")
    setup_parser = subparsers.add_parser("setup", help="interactive configuration wizard")
    setup_parser.add_argument("--config-path", help="path to the YAML config file to create or update")
    setup_parser.add_argument("--mode", help="deployment mode: edge, hub, or all-in-one")
    setup_parser.add_argument("--sensor-id")
    setup_parser.add_argument("--interface")
    setup_parser.add_argument("--hub-url")
    setup_parser.add_argument("--api-key")
    setup_parser.add_argument("--send-interval", type=float)
    setup_parser.add_argument("--hub-host")
    setup_parser.add_argument("--hub-port", type=int)
    setup_parser.add_argument("--hub-database")
    setup_parser.add_argument("--dashboard-host")
    setup_parser.add_argument("--dashboard-port", type=int)
    setup_parser.add_argument("--dashboard-username")
    setup_parser.add_argument("--dashboard-password")
    setup_parser.add_argument("--session-secret")
    setup_parser.add_argument("--force", action="store_true", help="overwrite an existing config file without prompting")
    setup_parser.add_argument("--non-interactive", action="store_true", help="run setup without prompting for missing values")
    setup_parser.add_argument("--check", action="store_true", help="validate the selected config without changing it")
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
    run_parser.add_argument("--host", default=None)
    run_parser.add_argument("--port", type=int, default=None)
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
    simulate_parser.add_argument("--scenario", default=None)
    simulate_parser.add_argument("--count", type=int, default=1)
    simulate_parser.add_argument("--sensor-id")
    simulate_subparsers = simulate_parser.add_subparsers(dest="simulate_command")
    for scenario in Scenario:
        aliases = []
        if scenario == Scenario.HIGH_TRAFFIC:
            aliases.append("anomaly")
        if scenario == Scenario.MIXED_ANOMALOUS:
            aliases.append("mixed")
        scenario_parser = simulate_subparsers.add_parser(
            scenario.value,
            aliases=aliases,
            help=f"generate {scenario.value} synthetic telemetry",
        )
        scenario_parser.add_argument("--count", type=int, default=1)
        scenario_parser.add_argument("--interval", type=float, default=0.0)
        scenario_parser.add_argument("--sensor-id")
    alerts_parser = subparsers.add_parser("alerts", help="local investigation alert commands")
    alerts_subparsers = alerts_parser.add_subparsers(dest="alerts_command")
    alerts_subparsers.add_parser("status", help="show alert engine status")
    alerts_subparsers.add_parser("list", help="list recent alerts")
    alerts_subparsers.add_parser("email-test", help="send an explicitly requested SMTP test message")
    investigation_parser = subparsers.add_parser("investigation", help="manage local Hub investigations")
    investigation_subparsers = investigation_parser.add_subparsers(dest="investigation_command")
    investigation_create = investigation_subparsers.add_parser("create", help="create an investigation")
    investigation_create.add_argument("--title", required=True)
    investigation_create.add_argument("--description", default="")
    investigation_create.add_argument("--device-id")
    investigation_create.add_argument("--sensor-id")
    investigation_show = investigation_subparsers.add_parser("show", help="show an investigation")
    investigation_show.add_argument("investigation_id")
    investigation_timeline = investigation_subparsers.add_parser("timeline", help="show an investigation timeline")
    investigation_timeline.add_argument("investigation_id")
    investigation_notes = investigation_subparsers.add_parser("notes", help="show analyst notes for an investigation")
    investigation_notes.add_argument("investigation_id")
    investigation_close = investigation_subparsers.add_parser("close", help="close a resolved investigation")
    investigation_close.add_argument("investigation_id")
    demo_parser = subparsers.add_parser("demo", help="run a safe synthetic demo across the ROCKS pipeline")
    demo_parser.add_argument("--mode", choices=[mode.value for mode in DemoMode], default=DemoMode.FULL.value)
    demo_parser.add_argument("--scenario", default=None)
    demo_parser.add_argument("--count", type=int, default=1)
    demo_parser.add_argument("--sensor-id", default="ROCKS-DEMO-01")
    demo_parser.set_defaults(demo_command=True)
    return parser


def _normalize_setup_mode(mode: str) -> str:
    normalized = str(mode).strip().lower().replace("_", "-")
    if normalized in {"all-in-one", "allinone", "edge+hub"}:
        return "all-in-one"
    if normalized in {"edge", "hub"}:
        return normalized
    raise ValueError(f"Unsupported setup mode: {mode}")


def _prompt_value(prompt: str, default: str = "", *, hide: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    value = getpass.getpass(f"{prompt}{suffix}: ") if hide else input(f"{prompt}{suffix}: ")
    if not value.strip():
        return default
    return value.strip()


def _available_interfaces() -> list[str]:
    try:
        return [name for _, name in socket.if_nameindex()]
    except OSError as exc:
        raise ValueError(f"Unable to list network interfaces: {exc}") from exc


def _validate_http_url(value: str, label: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must be a valid http(s) URL.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} contains an invalid port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"{label} contains an invalid port.")


def _choose_interface(current: str = "") -> str:
    all_interfaces = _available_interfaces()
    if not all_interfaces:
        raise ValueError("No network interfaces are available for Edge setup.")
    interfaces = physical_interfaces(all_interfaces) or all_interfaces
    if physical_interfaces(all_interfaces):
        print("Detected active physical network interfaces:")
        print("  A. Show all interfaces (advanced)")
    else:
        print("No active physical interface was detected; showing available interfaces.")
    print("Available network interfaces:")
    for index, name in enumerate(interfaces, start=1):
        selected = " (configured)" if name == current else ""
        print(f"  {index}. {name}{selected}")
    default = str(interfaces.index(current) + 1) if current in interfaces else ""
    while True:
        choice = _prompt_value("Select interface number/name" + (" or A for advanced" if physical_interfaces(all_interfaces) else ""), default=default)
        if choice.lower() in {"a", "advanced"} and physical_interfaces(all_interfaces):
            interfaces = all_interfaces
            print("Advanced interface list:")
            for index, name in enumerate(interfaces, start=1):
                print(f"  {index}. {name}")
            default = str(interfaces.index(current) + 1) if current in interfaces else ""
            continue
        if choice in interfaces:
            return choice
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]
        print("Select one of the listed interfaces.", file=sys.stderr)


def _validate_setup_config(config: dict[str, object], *, require_registration_key: bool = True) -> None:
    deployment = config.get("deployment", {})
    mode = str(deployment.get("mode", ""))
    if mode not in {"edge", "hub", "all-in-one"}:
        raise ValueError("Deployment mode must be edge, hub, or all-in-one.")
    edge = config.get("edge", {})
    hub = config.get("hub", {})
    dashboard = config.get("dashboard", {})
    storage = config.get("storage", {})
    if mode in {"edge", "all-in-one"}:
        sensor_id = str(edge.get("sensor_id", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", sensor_id):
            raise ValueError("Sensor ID must be 1-64 characters using letters, digits, dot, underscore, colon, or hyphen.")
        interface = str(edge.get("interface", "")).strip()
        if not interface:
            raise ValueError("A capture interface is required for live Edge observation.")
        if interface not in _available_interfaces():
            raise ValueError(f"Network interface {interface!r} is not available on this system.")
        hub_url = str(edge.get("hub_url", "")).strip()
        _validate_http_url(hub_url, "The Hub URL")
        try:
            send_interval = float(edge.get("send_interval_seconds", 5))
        except (TypeError, ValueError) as exc:
            raise ValueError("Edge send interval must be a positive number.") from exc
        if not math.isfinite(send_interval) or send_interval <= 0:
            raise ValueError("Edge send interval must be a positive number.")
        validate_positive_integer(edge.get("max_active_flows", 10_000), field="edge.max_active_flows")
        if mode == "edge" and not str(hub.get("api_key", "")).strip():
            raise ValueError("An Edge API key is required for Edge deployment.")
        if mode == "all-in-one" and require_registration_key and not str(hub.get("api_key", "")).strip():
            raise ValueError("The local Edge registration API key has not been configured.")
    if mode in {"hub", "all-in-one"}:
        hub_url = str(hub.get("url", "")).strip()
        _validate_http_url(hub_url, "The Hub URL")
        dashboard_username = str(dashboard.get("admin_username", "")).strip()
        dashboard_password_hash = str(dashboard.get("admin_password_hash", "")).strip()
        if not dashboard_username:
            raise ValueError("A dashboard administrator username is required.")
        if not dashboard_password_hash:
            raise ValueError("A dashboard administrator password is required.")
        if not str(dashboard.get("session_secret", "")).strip():
            raise ValueError("A dashboard session secret is required.")
        try:
            hub_port = int(hub.get("port", 8000))
            dashboard_port = int(dashboard.get("port", 8000))
        except (TypeError, ValueError) as exc:
            raise ValueError("Hub and dashboard ports must be integers from 1 to 65535.") from exc
        if not 1 <= hub_port <= 65535 or not 1 <= dashboard_port <= 65535:
            raise ValueError("Hub and dashboard ports must be integers from 1 to 65535.")
        if hub_port != dashboard_port:
            raise ValueError(
                "The Hub API and Dashboard share one listener in this deployment; configure the same port for both."
            )
        if not isinstance(storage, dict):
            raise ValueError("Storage configuration must be a mapping.")


def _run_installer(args: argparse.Namespace) -> int:
    platform = detect_platform()
    if platform != "linux":
        raise ValueError("ROCKS installation is only supported on Linux hosts.")
    if not python_version_supported():
        raise ValueError("ROCKS requires Python 3.10 or newer.")
    if os.geteuid() == 0:
        raise ValueError("Run the installer as your normal account; it requests sudo only to install system services.")

    config_path = Path(args.config_path) if args.config_path else Path(get_config_path())
    requested_mode = _normalize_setup_mode(args.mode) if args.mode else None
    if not Path(sys.executable).is_file():
        raise ValueError("The active Python interpreter is unavailable.")
    if not ServiceManager(config_path=config_path).systemd_check():
        raise ValueError("An active systemd manager is required to complete ROCKS installation.")
    sudo_executable = shutil.which("sudo")
    if not sudo_executable:
        raise ValueError("sudo is required to install systemd services. Install sudo or ask your system administrator.")

    existing_config = config_path.is_file()
    if existing_config and not args.force and requested_mode:
        configured_mode = str(load_config(config_path).get("deployment", {}).get("mode", ""))
        if requested_mode != configured_mode:
            raise ValueError(
                f"Existing configuration uses deployment mode {configured_mode!r}; pass --force to reconfigure it."
            )
    if args.non_interactive and (not existing_config or args.force):
        raise ValueError("Non-interactive installation requires an existing config and cannot be combined with --force.")
    if (
        getattr(args, "hub_port", None) is not None
        and getattr(args, "dashboard_port", None) is not None
        and args.hub_port != args.dashboard_port
    ):
        raise ValueError("The Hub API and Dashboard share one listener; --hub-port and --dashboard-port must match.")
    if not args.non_interactive and not args.force and not existing_config and not sys.stdin.isatty():
        raise ValueError("First-time installation needs a terminal for the guided setup. Run ./install-rocks.sh in a terminal.")

    setup_args = argparse.Namespace(
        config_path=str(config_path),
        mode=requested_mode,
        sensor_id=None,
        interface=None,
        hub_url=None,
        api_key=None,
        send_interval=None,
        hub_host=None,
        hub_port=None,
        hub_database=None,
        dashboard_host=None,
        dashboard_port=None,
        dashboard_username=None,
        dashboard_password=None,
        session_secret=None,
        force=bool(args.force),
        non_interactive=bool(args.non_interactive),
        check=existing_config and not args.force,
    )
    print("ROCKS installer: checking Linux, Python, systemd, and administrator access.")
    print(f"Platform: {platform} | Python: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    if existing_config and not args.force:
        print(f"Existing configuration found at {config_path}; it will be validated and preserved.")
    setup_result = _setup_config(setup_args)
    if setup_result != 0:
        return setup_result

    config = load_config(config_path)
    mode = str(config.get("deployment", {}).get("mode", ""))
    units = ServiceManager(config_path=config_path)
    deployment_unit_names = {
        "edge": ["rocks-edge.service"],
        "hub": ["rocks-hub.service"],
        "all-in-one": ["rocks-edge.service", "rocks-hub.service"],
    }.get(mode, [])
    previously_active: set[str] = set()
    try:
        previously_active = {
            unit_name
            for unit_name, active, _enabled in units.status()
            if active == "active"
        }
    except ServiceManagerError:
        pass
    cleanup_units = [unit_name for unit_name in deployment_unit_names if unit_name not in previously_active]
    if mode in {"hub", "all-in-one"}:
        dashboard_config = config.get("dashboard", {})
        bind_host = str(dashboard_config.get("host", "127.0.0.1"))
        bind_port = int(dashboard_config.get("port", 8000))
        if not listener_port_available(bind_host, bind_port):
            existing_report = HealthChecker(config_path=config_path).run() if existing_config and not args.force else None
            existing_checks = {check.name: check for check in existing_report.checks} if existing_report else {}
            if not (
                existing_checks.get("hub_service")
                and existing_checks["hub_service"].status == HealthStatus.OK
                and existing_checks.get("hub_api")
                and existing_checks["hub_api"].status == HealthStatus.OK
            ):
                return _installer_failed(
                    "Hub/Dashboard port",
                    f"Port {bind_port} on {bind_host} is already in use by another process.",
                    sudo_executable,
                    deployment_unit_names,
                )

    command = service_install_command(sudo_executable, sys.executable, config_path)
    try:
        service_result = subprocess.run(command, check=False)
    except OSError as exc:
        return _installer_failed(
            "systemd installation",
            f"Unable to run service installation ({type(exc).__name__}).",
            sudo_executable,
            cleanup_units,
            stop_services=bool(cleanup_units),
        )
    if service_result.returncode != 0:
        return _installer_failed(
            "systemd installation",
            "The existing ROCKS service manager returned an error.",
            sudo_executable,
            cleanup_units,
            exit_code=service_result.returncode,
            stop_services=bool(cleanup_units),
        )

    dashboard_config = config.get("dashboard", {})
    final_url = dashboard_url(
        str(dashboard_config.get("host", "127.0.0.1")),
        int(dashboard_config.get("port", 8000)),
    ) if mode in {"hub", "all-in-one"} else ""

    required = {"configuration"}
    if mode in {"edge", "all-in-one"}:
        required.update({"edge_service", "edge_storage", "edge_buffer", "hub_api"})
    if mode in {"hub", "all-in-one"}:
        required.update({"hub_service", "hub_database", "hub_api", "dashboard"})
    deadline = time.monotonic() + 30
    report = HealthChecker(config_path=config_path).run()
    verification_error: str | None = None
    services_verified = False
    while time.monotonic() < deadline:
        checks = {check.name: check for check in report.checks}
        try:
            units.verify()
            services_verified = True
            verification_error = None
        except ServiceManagerError as exc:
            services_verified = False
            verification_error = str(exc)
        if services_verified and required.issubset(checks) and all(
            checks[name].status == HealthStatus.OK for name in required
        ):
            break
        time.sleep(1)
        report = HealthChecker(config_path=config_path).run()
    checks = {check.name: check for check in report.checks}
    for check in report.checks:
        print(f"Health: {check.name} {check.status.value}")
    if not services_verified or not required.issubset(checks) or any(
        checks[name].status != HealthStatus.OK for name in required
    ):
        failed_checks = [name for name in required if name not in checks or checks[name].status != HealthStatus.OK]
        health_details = "; ".join(
            f"{name}: {checks[name].message if name in checks else 'check unavailable'}"
            for name in sorted(failed_checks)
        )
        failure_detail = verification_error or ("Health checks failed: " + health_details)
        return _installer_failed(
            "service/runtime health",
            failure_detail,
            sudo_executable,
            cleanup_units,
            stop_services=bool(cleanup_units),
        )

    print("ROCKS READY")
    if final_url:
        print(f"Dashboard URL: {final_url}")
    return 0


def _installer_failed(
    component: str,
    detail: str,
    sudo_executable: str,
    units: list[str],
    *,
    exit_code: int = 1,
    stop_services: bool = False,
) -> int:
    if units and stop_services:
        try:
            subprocess.run([sudo_executable, "-n", "systemctl", "stop", *units], check=False, capture_output=True, text=True)
        except OSError:
            pass
    print("INSTALLATION FAILED: ROCKS installation could not be completed.", file=sys.stderr)
    print(f"Failed component: {component}", file=sys.stderr)
    print(detail, file=sys.stderr)
    print("Diagnostics:", file=sys.stderr)
    print("  ./.venv/bin/rocks health verbose", file=sys.stderr)
    print("  ./.venv/bin/rocks service status", file=sys.stderr)
    print("  journalctl -u rocks-edge.service -u rocks-hub.service --no-pager -n 50", file=sys.stderr)
    return exit_code


def _setup_config(args: argparse.Namespace) -> int:
    config_path = Path(args.config_path) if args.config_path else Path(get_config_path())
    if config_path.resolve() == DEFAULT_CONFIG_TEMPLATE_PATH.resolve():
        raise ValueError("The tracked example configuration is read-only; choose a separate config path.")
    if (
        args.hub_port is not None
        and args.dashboard_port is not None
        and args.hub_port != args.dashboard_port
    ):
        raise ValueError("The Hub API and Dashboard share one listener; --hub-port and --dashboard-port must match.")
    if args.check:
        config = load_config(config_path)
        _validate_setup_config(config)
        print(f"ROCKS configuration is valid: {config_path}")
        return 0

    if args.non_interactive and not args.mode:
        raise ValueError("Non-interactive setup requires --mode.")
    if not args.non_interactive and not sys.stdin.isatty():
        raise ValueError("Interactive setup requires a terminal; use --non-interactive with explicit settings.")

    if args.mode:
        mode = _normalize_setup_mode(args.mode)
    else:
        print("ROCKS Fleet Setup\n==================")
        print("1. Edge Sensor\n2. Hub / Command Center\n3. Edge + Hub (single machine)")
        mode_choice = _prompt_value("Select deployment mode (1-3)")
        modes = {"1": "edge", "2": "hub", "3": "all-in-one"}
        if mode_choice not in modes:
            raise ValueError("Select deployment mode 1, 2, or 3.")
        mode = modes[mode_choice]
    config_path = Path(args.config_path) if args.config_path else Path(get_config_path())

    if config_path.exists() and not args.force:
        if args.non_interactive:
            raise ValueError(f"Config file already exists at {config_path}; pass --force to update it.")
        response = _prompt_value(f"Config file already exists at {config_path}. Update it? [y/N]", default="n")
        if response.lower() not in {"y", "yes"}:
            print(f"Setup cancelled. Existing config kept at {config_path}")
            return 0

    if config_path.exists():
        existing = load_config(config_path)
    else:
        existing = build_default_config()

    config = existing.copy()
    config.setdefault("project", {})
    config.setdefault("deployment", {})
    config.setdefault("edge", {})
    config.setdefault("hub", {})
    config.setdefault("telemetry", {})
    config.setdefault("storage", {})
    config.setdefault("dashboard", {})

    config["deployment"]["mode"] = mode

    if not args.non_interactive:
        print("\nThis wizard configures ROCKS software only; it does not configure switches or network infrastructure.")
        if mode in {"edge", "all-in-one"}:
            config["edge"]["sensor_id"] = _prompt_value("Edge sensor ID", default=str(config["edge"].get("sensor_id", "ROCKS-EDGE-01")))
            config["edge"]["interface"] = _choose_interface(str(config["edge"].get("interface", "")))
            if mode == "edge":
                config["edge"]["hub_url"] = _prompt_value("Hub URL", default=str(config["edge"].get("hub_url", "http://127.0.0.1:8000")))
            if mode == "edge":
                config["hub"]["api_key"] = _prompt_value("Edge API key", hide=True) or str(config["hub"].get("api_key", ""))
            config["edge"]["send_interval_seconds"] = float(
                _prompt_value("Send interval in seconds", default=str(config["edge"].get("send_interval_seconds", 5)))
            )
        if mode in {"hub", "all-in-one"}:
            if mode == "hub":
                config["hub"]["url"] = _prompt_value("Hub URL", default=str(config["hub"].get("url", "http://127.0.0.1:8000")))
            bind_host = _prompt_value("Hub and Dashboard bind host", default=str(config["dashboard"].get("host", "127.0.0.1")))
            config["hub"]["host"] = bind_host
            config["storage"]["hub_database"] = _prompt_value(
                "Hub SQLite database path", default=str(config["storage"].get("hub_database") or data_dir() / "rocks-hub.db")
            )
            config["dashboard"]["admin_username"] = _prompt_value("Dashboard admin username", default=str(config["dashboard"].get("admin_username", "admin")))
            password = _prompt_value("Dashboard admin password", hide=True)
            confirmation = _prompt_value("Confirm dashboard admin password", hide=True)
            if not password or password != confirmation:
                raise ValueError("A non-empty dashboard password must be entered identically twice.")
            config["dashboard"]["admin_password_hash"] = hash_password(password)
            config["dashboard"]["session_secret"] = str(config["dashboard"].get("session_secret") or secrets.token_urlsafe(48))
            config["dashboard"]["host"] = bind_host
            shared_port = int(_prompt_value("Hub and Dashboard port", default=str(config["dashboard"].get("port", config["hub"].get("port", 8000)))))
            config["hub"]["port"] = shared_port
            config["dashboard"]["port"] = shared_port
            if mode == "all-in-one":
                local_host = "127.0.0.1" if bind_host in {"", "0.0.0.0", "::"} else bind_host
                config["edge"]["hub_url"] = f"http://{local_host}:{shared_port}"
                config["hub"]["url"] = config["edge"]["hub_url"]
    else:
        if mode in {"edge", "all-in-one"}:
            config["edge"]["sensor_id"] = str(args.sensor_id if args.sensor_id is not None else config["edge"].get("sensor_id", "")).strip()
            config["edge"]["interface"] = str(args.interface if args.interface is not None else config["edge"].get("interface", "")).strip()
            config["edge"]["hub_url"] = str(args.hub_url if args.hub_url is not None else config["edge"].get("hub_url", "")).strip()
            config["edge"]["send_interval_seconds"] = args.send_interval if args.send_interval is not None else config["edge"].get("send_interval_seconds", 5)
            if mode == "edge":
                config["hub"]["api_key"] = str(args.api_key if args.api_key is not None else config["hub"].get("api_key", "")).strip()
        if mode in {"hub", "all-in-one"}:
            config["hub"]["url"] = str(args.hub_url or config["hub"].get("url") or "http://127.0.0.1:8000").strip()
            config["hub"]["host"] = str(args.hub_host or config["hub"].get("host", "127.0.0.1")).strip()
            shared_port = (
                args.dashboard_port
                if args.dashboard_port is not None
                else args.hub_port
                if args.hub_port is not None
                else config["dashboard"].get("port", config["hub"].get("port", 8000))
            )
            config["hub"]["port"] = shared_port
            config["storage"]["hub_database"] = str(args.hub_database or config["storage"].get("hub_database") or data_dir() / "rocks-hub.db").strip()
            config["dashboard"]["admin_username"] = str(args.dashboard_username if args.dashboard_username is not None else config["dashboard"].get("admin_username", "")).strip()
            if args.dashboard_password:
                config["dashboard"]["admin_password_hash"] = hash_password(args.dashboard_password)
            config["dashboard"]["session_secret"] = str(args.session_secret or config["dashboard"].get("session_secret") or secrets.token_urlsafe(48)).strip()
            config["dashboard"]["host"] = str(args.dashboard_host or config["dashboard"].get("host", "127.0.0.1")).strip()
            config["dashboard"]["port"] = shared_port

    if mode in {"edge", "all-in-one"}:
        config["edge"]["enabled"] = True
    else:
        config["edge"]["enabled"] = False

    if mode in {"hub", "all-in-one"}:
        config["hub"]["enabled"] = True
        config["dashboard"]["enabled"] = True
        if mode == "all-in-one":
            local_host = "127.0.0.1" if config["dashboard"].get("host") in {"", "0.0.0.0", "::"} else str(config["dashboard"].get("host"))
            local_url = service_base_url(local_host, int(config["dashboard"]["port"]))
            config["hub"]["url"] = local_url
            config["edge"]["hub_url"] = local_url
        else:
            config["hub"]["url"] = str(config["hub"].get("url") or "http://127.0.0.1:8000").strip()
        config.setdefault("ml", {})["enabled"] = True
        config.setdefault("alerts", {})["enabled"] = True
    else:
        config["hub"]["enabled"] = False
        config["dashboard"]["enabled"] = False

    _validate_setup_config(config, require_registration_key=mode == "edge")
    if mode == "all-in-one":
        hub_database = Path(str(config["storage"].get("hub_database") or data_dir() / "rocks-hub.db")).expanduser()
        storage = HubStorage(hub_database)
        registry = EdgeRegistry(storage)
        sensor_id = str(config["edge"]["sensor_id"])
        existing_edge = registry.get(sensor_id)
        configured_key = str(args.api_key or config["hub"].get("api_key", ""))
        if existing_edge:
            if not configured_key or not registry.authenticate(sensor_id, configured_key):
                raise ValueError(f"Sensor {sensor_id} is already registered; its API key cannot be recovered. Use a new sensor ID or retain its existing key.")
        elif args.api_key:
            storage.register_edge(sensor_id, sensor_id, hash_api_key(args.api_key))
        else:
            _, configured_key = registry.register(sensor_id)
        config["hub"]["api_key"] = configured_key

    _validate_setup_config(config)
    path = write_config(config, config_path)
    print("\nROCKS Fleet Setup Complete")
    print(f"Mode: {mode}")
    if mode in {"edge", "all-in-one"}:
        print(f"Sensor ID: {config['edge']['sensor_id']}")
        print(f"Interface: {config['edge']['interface']}")
        print(f"Hub: {config['edge']['hub_url']}")
        print("API key: configured")
    if mode in {"hub", "all-in-one"}:
        print(f"Dashboard administrator: {config['dashboard']['admin_username']}")
        print(f"Hub database: {config['storage']['hub_database']}")
        print("Dashboard password: configured")
        print("Session secret: generated/configured")
    print(f"Configuration: {path}")
    print("\nNext steps:")
    if mode in {"edge", "all-in-one"}:
        print("1. Connect the selected interface to an appropriate SPAN/mirror/TAP observation point.")
        print("2. Run: rocks edge test")
        print("3. Start: rocks edge run")
    if mode in {"hub", "all-in-one"}:
        print("Start the Hub and dashboard with: rocks dashboard run")
    print("ROCKS setup configures software only; it does not configure switches, TAPs, routers, firewalls, or network topology.")
    return 0


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

    if args.command == "version":
        print(f"ROCKS Fleet {__version__}")
        return 0

    if args.command == "status":
        print("ROCKS Fleet foundation is installed.")
        print("No Edge or Hub services are running yet.")
        return 0

    if args.command == "config":
        print(f"ROCKS configuration path: {get_config_path()}")
        return 0

    if args.command == "setup":
        try:
            return _setup_config(args)
        except (ValueError, FileNotFoundError) as exc:
            print(f"ROCKS setup error: {exc}", file=sys.stderr)
            return 2

    if args.command == "install":
        try:
            return _run_installer(args)
        except (ValueError, FileNotFoundError) as exc:
            return _installer_failed(
                "preflight/configuration",
                str(exc),
                shutil.which("sudo") or "sudo",
                [],
                exit_code=2,
            )

    if args.command == "logs":
        print("ROCKS logs are emitted through the configured Python logger and systemd journal when services run.")
        print("Use: journalctl -u rocks-edge.service -u rocks-hub.service")
        return 0

    if args.command == "test":
        print("ROCKS CLI smoke test command passed; it does not run pytest.")
        print("Use: .venv/bin/python -m pytest -q")
        return 0

    if args.command == "health":
        report = HealthChecker().run()
        print("ROCKS Fleet Health")
        print("------------------")
        for check in report.checks:
            label = check.name.replace("_", " ").title()
            label = label.replace("Api", "API").replace("Id", "ID").replace("Sqlite", "SQLite")
            print(f"{label}: {check.status.value} - {check.message}")
            if args.view == "verbose":
                for key, value in check.details.items():
                    detail_label = key.replace("_", " ").title()
                    detail_label = detail_label.replace("Api", "API").replace("Id", "ID").replace("Sqlite", "SQLite")
                    print(f"  {detail_label}: {value}")
                if check.hint:
                    print(f"  Hint: {check.hint}")
        print(f"Overall: {report.overall.value}")
        return report.exit_code

    if args.command == "detection":
        try:
            detection_config = get_detection_config()
            engine = DetectionEngine(detection_config)
            if args.detection_command == "status":
                print(f"Deterministic detection: {'ENABLED' if detection_config.enabled else 'DISABLED'}")
                print(f"Window seconds: {detection_config.window_seconds:g}")
                print(f"High traffic rate threshold: {detection_config.high_traffic_rate:g}")
                print(f"Connection burst rate threshold: {detection_config.connection_burst_rate:g}")
                print(f"Unique destination threshold: {detection_config.unique_destination_count}")
                print(f"Reconnect count threshold: {detection_config.reconnect_count}")
                print("Thresholds are deployment-specific indicators, not proof of an attack.")
                return 0
            if args.detection_command == "test":
                for scenario in (
                    Scenario.NORMAL,
                    Scenario.HIGH_TRAFFIC,
                    Scenario.RECONNAISSANCE_LIKE,
                    Scenario.DNS_ANOMALY,
                    Scenario.RECONNECT_STORM,
                    Scenario.DEAUTH_RELATED_SIMULATION,
                ):
                    record = generate_records(scenario, count=1)[0]
                    assessment = engine.assess(record)
                    rule_ids = ", ".join(rule.rule_id for rule in assessment.rules_triggered) or "none"
                    simulation = " [SIMULATION ONLY]" if assessment.simulation else ""
                    print(f"{scenario.value}: {assessment.severity}; rules={rule_ids}{simulation}")
                print("Synthetic data only; no network traffic was generated.")
                return 0
        except (ValueError, OSError) as exc:
            print(f"ROCKS detection error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        parser.parse_args(["detection", "--help"])
        return 0

    if args.command == "service":
        manager = ServiceManager()
        try:
            if args.service_command == "generate":
                for path in manager.generate(args.output_dir):
                    print(f"Generated: {path}")
                return 0
            if args.service_command == "install":
                installed = manager.install()
                print("Installed service units; systemd accepted enable/start requests: " + ", ".join(installed))
                print("Runtime state is not confirmed by the start request; run 'rocks service verify' or 'rocks install' for health verification.")
                log_units = " ".join(f"-u {unit_name}" for unit_name in installed)
                print(f"Logs: journalctl {log_units} -f")
                return 0
            if args.service_command == "uninstall":
                removed = manager.uninstall()
                print("Removed service units: " + ", ".join(removed))
                return 0
            if args.service_command in {"start", "stop", "restart"}:
                for unit_name, active, enabled in manager.operate(args.service_command):
                    print(f"{unit_name}: {active} (enabled: {enabled})")
                return 0
            if args.service_command == "status":
                for unit_name, active, enabled in manager.status():
                    print(f"{unit_name}: {active} (enabled: {enabled})")
                return 0
            if args.service_command == "verify":
                for unit_name, properties in manager.verify():
                    print(f"{unit_name}: {properties['ActiveState']}/{properties['SubState']} (enabled: {properties['UnitFileState']})")
                return 0
        except ServiceManagerError as exc:
            print(f"ROCKS service error: {exc}", file=sys.stderr)
            return 2
        parser.parse_args(["service", "--help"])
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

            uvicorn.run(
                create_app(str(config.database_path)),
                host=args.host or config.host,
                port=args.port or config.port,
            )
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
        scenario_name = args.simulate_command or getattr(args, "scenario", None)
        if scenario_name is None:
            scenario_name = "normal"
        try:
            scenario = normalize_demo_scenario(scenario_name)
        except ValueError as exc:
            print(f"ROCKS simulate error: {exc}", file=sys.stderr)
            return 2
        edge_values = get_edge_agent_config()
        configured_sensor_id = edge_values["sensor_id"]
        requested_sensor_id = getattr(args, "sensor_id", None)
        if requested_sensor_id and requested_sensor_id != configured_sensor_id:
            print(
                "ROCKS simulate error: --sensor-id must match the configured Edge sensor; "
                "configure credentials authorized for that sensor before delivering telemetry.",
                file=sys.stderr,
            )
            return 2
        sensor_id = requested_sensor_id or configured_sensor_id
        records = generate_records(
            scenario,
            count=args.count,
            sensor_id=sensor_id,
            start=datetime.now(timezone.utc) - timedelta(minutes=max(0, args.count - 1)),
        )
        simulation = any(record.payload.get("simulation") for record in records)
        print(f"Generated {len(records)} safe synthetic {scenario.value} telemetry records.")
        print(f"Scenario: {scenario.value}")
        print(f"Sensor ID: {sensor_id}")
        print("Synthetic data: yes")
        print(f"Explicit simulation marker: {'yes' if simulation else 'no'}")
        print("No live packets or external attack activity were generated.")
        if edge_values["hub_url"] and edge_values["api_key"]:
            with tempfile.TemporaryDirectory(prefix="rocks-simulate-") as directory:
                edge_values["database_path"] = Path(directory) / "telemetry.db"
                edge_values["buffer_path"] = Path(directory) / "buffer.db"
                result = EdgeAgent(EdgeAgentConfig(**edge_values)).run_dry_run(records)
            print(f"Hub delivery: sent={result.sent} failed={result.failed}")
            if result.failed or result.sent != len(records):
                return 1
        else:
            print("Hub delivery: not configured; records were generated only")
        return 0

    if args.command == "alerts":
        if args.alerts_command == "email-test":
            try:
                result = EmailNotificationService(get_email_config()).send_test()
            except NotificationError as exc:
                print(f"SMTP test: FAILED ({exc.reason})", file=sys.stderr)
                return 1
            except (OSError, RuntimeError, TypeError, ValueError):
                print("SMTP test: FAILED (smtp_configuration_invalid)", file=sys.stderr)
                return 1
            print("Email notifications: DISABLED" if result.status == "DISABLED" else f"SMTP test: {result.message}")
            return 0
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

    if args.command == "investigation":
        storage = HubStorage(get_hub_config().database_path)
        try:
            if args.investigation_command == "create":
                title = validate_case_text(args.title, field="title", required=True, maximum=200)
                description = validate_case_text(args.description, field="description", required=False, maximum=4000)
                device_id = validate_identifier(args.device_id, field="device_id") if args.device_id else None
                sensor_id = validate_identifier(args.sensor_id, field="sensor_id") if args.sensor_id else None
                investigation = storage.create_investigation(
                    title=title,
                    description=description,
                    device_id=device_id,
                    sensor_id=sensor_id,
                )
                print(json.dumps(investigation, indent=2))
                return 0
            investigation_id = validate_investigation_id(args.investigation_id)
            if args.investigation_command == "show":
                investigation = storage.get_investigation(investigation_id)
                if investigation is None:
                    print("Investigation not found.", file=sys.stderr)
                    return 2
                print(json.dumps(investigation, indent=2))
                return 0
            if args.investigation_command == "timeline":
                events = storage.investigation_events(investigation_id)
                if events is None:
                    print("Investigation not found.", file=sys.stderr)
                    return 2
                print(json.dumps(events, indent=2))
                return 0
            if args.investigation_command == "notes":
                notes = storage.investigation_notes(investigation_id)
                if notes is None:
                    print("Investigation not found.", file=sys.stderr)
                    return 2
                for note in notes:
                    category = f" [{note['category']}]" if note["category"] else ""
                    print(f"{note['timestamp']} {note['author']}{category}: {note['note_text']}")
                return 0
            if args.investigation_command == "close":
                investigation = storage.close_investigation(investigation_id)
                if investigation is None:
                    print("Investigation not found.", file=sys.stderr)
                    return 2
                print(json.dumps(investigation, indent=2))
                return 0
        except ValueError as exc:
            print(f"ROCKS investigation error: {exc}", file=sys.stderr)
            return 2
        parser.parse_args(["investigation", "--help"])
        return 0

    if args.command == "demo":
        try:
            if args.scenario is not None:
                scenario_value = normalize_demo_scenario(args.scenario)
            else:
                scenario_value = None
            result = run_demo_sequence(
                mode=args.mode,
                scenario=scenario_value,
                count=args.count,
                sensor_id=args.sensor_id,
            )
        except ValueError as exc:
            print(f"ROCKS demo error: {exc}", file=sys.stderr)
            return 2

        print("Synthetic ROCKS demo pipeline")
        print(f"Mode: {result['mode']}")
        print(f"Scenarios: {', '.join(result['scenarios'])}")
        print(f"Sensor ID: {result['sensor_id']}")
        print(f"Telemetry generated: {result['records_generated']}")
        print(f"Alerts created: {result['alerts']}")
        if result.get("investigation_id"):
            print(f"Investigation ID: {result['investigation_id']}")
        print(f"Simulation only: {result['synthetic']} | No real network traffic: {result['no_real_network_activity']}")
        return 0

    print(f"ROCKS Fleet {__version__}")
    print("")
    print("Usage: rocks [--version] [status|config|logs|test|install]")
    print("Run 'rocks --help' for more information.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
