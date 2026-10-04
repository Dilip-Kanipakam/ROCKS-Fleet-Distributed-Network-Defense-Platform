from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from rocks import cli
from rocks.cli import main
from rocks.config import load_config, write_config
from rocks.health import HealthCheck, HealthReport, HealthStatus
from rocks.installer import (
    dashboard_url,
    detect_platform,
    interface_choice,
    listener_port_available,
    physical_interfaces,
    python_version_supported,
    redact_secret,
    service_install_command,
)


def _hub_config(database: Path) -> dict:
    return {
        "deployment": {"mode": "hub"},
        "edge": {"enabled": False},
        "hub": {"enabled": True, "url": "http://127.0.0.1:8000", "host": "127.0.0.1", "port": 8000},
        "dashboard": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8000,
            "admin_username": "administrator",
            "admin_password_hash": "password-hash-never-print",
            "session_secret": "session-secret-never-print",
        },
        "storage": {"hub_database": str(database)},
        "telemetry": {"window_seconds": 60},
        "alerts": {"enabled": True},
    }


def _healthy_report() -> HealthReport:
    names = ("configuration", "hub_service", "hub_database", "hub_api", "dashboard")
    checks = tuple(HealthCheck(name, HealthStatus.OK, "ok") for name in names)
    return HealthReport(checks, HealthStatus.HEALTHY, "hub")


def _healthy_edge_report() -> HealthReport:
    names = ("configuration", "edge_service", "edge_storage", "edge_buffer", "hub_api")
    checks = tuple(HealthCheck(name, HealthStatus.OK, "ok") for name in names)
    return HealthReport(checks, HealthStatus.HEALTHY, "edge")


def _mock_installer_environment(monkeypatch, *, config_path: Path, health_reports=None):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "detect_platform", lambda: "linux")
    monkeypatch.setattr(cli, "python_version_supported", lambda: True)

    class MockServiceManager:
        def __init__(self, **_kwargs):
            self.systemd_check = lambda: True

        def status(self):
            return []

        def verify(self):
            return []

    monkeypatch.setattr(cli, "ServiceManager", MockServiceManager)
    monkeypatch.setattr(cli, "listener_port_available", lambda _host, _port: True)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/sudo" if name == "sudo" else None)
    commands = []

    def mock_run(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.subprocess, "run", mock_run)
    reports = list(health_reports or [_healthy_report()])

    class MockHealthChecker:
        def __init__(self, *, config_path):
            assert Path(config_path) == config_path_expected

        def run(self):
            return reports.pop(0) if len(reports) > 1 else reports[0]

    config_path_expected = config_path
    monkeypatch.setattr(cli, "HealthChecker", MockHealthChecker)
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)
    return commands


@pytest.mark.parametrize(
    ("platform", "expected"),
    [("linux", "linux"), ("linux2", "linux"), ("darwin", "unsupported")],
)
def test_detect_platform_reports_supported_linux(platform, expected):
    assert detect_platform(platform) == expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [((3, 9), False), ((3, 10), True), ((3, 12), True)],
)
def test_python_version_support(version, expected):
    assert python_version_supported(version) is expected


def test_interface_choice_prefers_non_loopback_and_existing_preference():
    assert interface_choice(["lo", "eth0", "wlan0"]) == "eth0"
    assert interface_choice(["lo", "eth0"], preferred="eth0") == "eth0"


def test_interface_choice_rejects_explicit_empty_list():
    with pytest.raises(ValueError, match="No network interfaces"):
        interface_choice([])


def test_physical_interfaces_omit_loopback_and_virtual_devices(tmp_path):
    sysfs = tmp_path / "sys-class-net"
    device = sysfs / "enp2s0"
    (device / "device").mkdir(parents=True)
    (device / "operstate").write_text("up\n", encoding="ascii")
    assert physical_interfaces(["lo", "docker0", "veth123", "enp2s0"], sysfs_root=sysfs) == ["enp2s0"]


def test_listener_port_probe_detects_occupied_and_free_ports():
    with __import__("socket").socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        assert not listener_port_available("127.0.0.1", port)
    assert listener_port_available("127.0.0.1", port)


def test_redact_secret_masks_sensitive_value():
    assert redact_secret("super-secret") != "super-secret"
    assert redact_secret("abc12345")[-2:] == "45"


def test_dashboard_url_uses_localhost_for_wildcard_and_formats_ipv6():
    assert dashboard_url("0.0.0.0", 8000) == "http://localhost:8000/dashboard"
    assert dashboard_url("::1", 8000) == "http://[::1]:8000/dashboard"


def test_service_install_command_passes_only_config_path_and_service_action(tmp_path):
    command = service_install_command("/usr/bin/sudo", "/opt/rocks/.venv/bin/python", tmp_path / "config.yaml")
    assert command == [
        "/usr/bin/sudo",
        "env",
        f"ROCKS_CONFIG_PATH={(tmp_path / 'config.yaml').resolve()}",
        "/opt/rocks/.venv/bin/python",
        "-m",
        "rocks",
        "service",
        "install",
    ]


def test_installer_runs_configuration_service_and_health_then_prints_ready(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_hub_config(tmp_path / "hub.db"), config_path)
    original = config_path.read_bytes()
    interpreter = tmp_path / ".venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.touch()
    monkeypatch.setattr(cli.sys, "executable", str(interpreter))
    commands = _mock_installer_environment(monkeypatch, config_path=config_path)

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    output = capsys.readouterr().out
    assert result == 0
    assert config_path.read_bytes() == original
    assert "Existing configuration found" in output
    assert "ROCKS READY" in output
    assert "Dashboard URL: http://127.0.0.1:8000/dashboard" in output
    assert len(commands) == 1
    assert commands[0][-2:] == ["service", "install"]
    assert commands[0][3] == str(interpreter)
    assert "password-hash-never-print" not in output
    assert "session-secret-never-print" not in output


def test_installer_retries_transient_edge_storage_readiness_failure(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    config = _hub_config(tmp_path / "hub.db")
    config["deployment"]["mode"] = "all-in-one"
    config["edge"] = {
        "enabled": True,
        "sensor_id": "EDGE-READY-01",
        "interface": "eth-test",
        "hub_url": "http://127.0.0.1:8000",
        "send_interval_seconds": 5,
    }
    config["hub"]["api_key"] = "edge-registration-key"
    config["storage"]["database"] = str(tmp_path / "data" / "edge.db")
    config["storage"]["buffer"] = str(tmp_path / "data" / "buffer.db")
    write_config(config, config_path)
    names = (
        "configuration", "edge_service", "edge_storage", "edge_buffer",
        "hub_service", "hub_database", "hub_api", "dashboard",
    )
    initializing_checks = tuple(
        HealthCheck(
            name,
            HealthStatus.ERROR if name == "edge_storage" else HealthStatus.OK,
            "SQLite storage is unavailable: unable to open database file"
            if name == "edge_storage"
            else "ok",
            details={"path": str(tmp_path / "data" / "edge.db")} if name == "edge_storage" else {},
        )
        for name in names
    )
    reports = [
        HealthReport(initializing_checks, HealthStatus.UNHEALTHY, "all-in-one"),
        HealthReport(
            tuple(HealthCheck(name, HealthStatus.OK, "ok") for name in names),
            HealthStatus.HEALTHY,
            "all-in-one",
        ),
    ]
    _mock_installer_environment(monkeypatch, config_path=config_path, health_reports=reports)
    monkeypatch.setattr(cli, "_available_interfaces", lambda: ["eth-test"])

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    output = capsys.readouterr()
    assert result == 0
    assert "Health: edge_storage OK" in output.out
    assert "ROCKS READY" in output.out
    assert not output.err


def test_installer_invokes_interactive_setup_for_first_install(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    commands = _mock_installer_environment(monkeypatch, config_path=config_path)
    monkeypatch.setattr(cli.sys, "stdin", type("Terminal", (), {"isatty": lambda _self: True})())
    setup_calls = []

    def mock_setup(setup_args):
        setup_calls.append(setup_args)
        write_config(_hub_config(tmp_path / "hub.db"), config_path)
        return 0

    monkeypatch.setattr(cli, "_setup_config", mock_setup)

    result = main(["install", "--config-path", str(config_path), "--mode", "hub"])

    assert result == 0
    assert len(setup_calls) == 1
    assert setup_calls[0].mode == "hub"
    assert setup_calls[0].check is False
    assert setup_calls[0].non_interactive is False
    assert "ROCKS READY" in capsys.readouterr().out
    assert len(commands) == 1


def test_fresh_all_in_one_install_runs_real_wizard_without_manual_steps(tmp_path, monkeypatch, capsys):
    import builtins

    config_path = tmp_path / "fresh config.yaml"
    commands = _mock_installer_environment(monkeypatch, config_path=config_path)
    healthy_names = (
        "configuration", "edge_service", "edge_storage", "edge_buffer",
        "hub_service", "hub_database", "hub_api", "dashboard",
    )
    monkeypatch.setattr(
        cli,
        "HealthChecker",
        lambda **_kwargs: type("Checker", (), {"run": lambda _self: HealthReport(
            tuple(HealthCheck(name, HealthStatus.OK, "ok") for name in healthy_names),
            HealthStatus.HEALTHY,
            "all-in-one",
        )})(),
    )
    monkeypatch.setattr(cli.sys, "stdin", type("Terminal", (), {"isatty": lambda _self: True})())
    monkeypatch.setattr(cli.socket, "if_nameindex", lambda: [(1, "eth-test")])
    answers = iter([
        "ROCKS-FRESH-01", "1", "5", "127.0.0.1", str(tmp_path / "hub.db"),
        "administrator", "18780",
    ])
    monkeypatch.setattr(builtins, "input", lambda _prompt: next(answers))
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "local-test-password")

    result = main(["install", "--config-path", str(config_path), "--mode", "all-in-one"])

    output = capsys.readouterr().out
    config = load_config(config_path)
    assert result == 0
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert config["deployment"]["mode"] == "all-in-one"
    assert config["hub"]["api_key"]
    assert config["dashboard"]["session_secret"]
    assert config["hub"]["port"] == config["dashboard"]["port"] == 18780
    assert config["edge"]["hub_url"] == "http://127.0.0.1:18780"
    assert "local-test-password" not in output
    assert config["hub"]["api_key"] not in output
    assert config["dashboard"]["session_secret"] not in output
    assert "ROCKS READY" in output
    assert "Dashboard URL: http://127.0.0.1:18780/dashboard" in output
    assert commands[0][0:3] == ["/usr/bin/sudo", "env", f"ROCKS_CONFIG_PATH={config_path.resolve()}"]


def test_installer_does_not_report_ready_when_required_health_fails(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    config = _hub_config(tmp_path / "hub.db")
    config["deployment"]["mode"] = "all-in-one"
    config["edge"] = {
        "enabled": True,
        "sensor_id": "EDGE-FAILED-01",
        "interface": "eth-test",
        "hub_url": "http://127.0.0.1:8000",
        "send_interval_seconds": 5,
    }
    config["hub"]["api_key"] = "edge-registration-key"
    edge_database = tmp_path / "data" / "edge.db"
    config["storage"]["database"] = str(edge_database)
    config["storage"]["buffer"] = str(tmp_path / "data" / "buffer.db")
    write_config(config, config_path)
    names = (
        "configuration", "edge_service", "edge_storage", "edge_buffer",
        "hub_service", "hub_database", "hub_api", "dashboard",
    )
    unhealthy_checks = tuple(
        HealthCheck(
            name,
            HealthStatus.ERROR if name == "edge_storage" else HealthStatus.OK,
            "SQLite storage is unavailable: unable to open database file"
            if name == "edge_storage"
            else "check",
            details={"path": str(edge_database)} if name == "edge_storage" else {},
            hint="Check storage.database and 'journalctl -u rocks-edge.service'."
            if name == "edge_storage"
            else "",
        )
        for name in names
    )
    report = HealthReport(unhealthy_checks, HealthStatus.UNHEALTHY, "all-in-one")
    _mock_installer_environment(monkeypatch, config_path=config_path, health_reports=[report])
    monkeypatch.setattr(cli, "_available_interfaces", lambda: ["eth-test"])
    times = iter((0.0, 31.0))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(times))

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    captured = capsys.readouterr()
    assert result == 1
    assert "ROCKS READY" not in captured.out
    assert "Failed component: service/runtime health" in captured.err
    assert "Runtime readiness was not confirmed within 30 seconds" in captured.err
    assert "SQLite storage is unavailable: unable to open database file" in captured.err
    assert f"path={edge_database}" in captured.err
    assert "recovery=Check storage.database and 'journalctl -u rocks-edge.service'." in captured.err
    assert "./.venv/bin/rocks health verbose" in captured.err


def test_edge_install_requires_reachable_remote_hub(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "edge.yaml"
    config = _hub_config(tmp_path / "hub.db")
    config["deployment"]["mode"] = "edge"
    config["edge"] = {
        "enabled": True,
        "sensor_id": "EDGE-01",
        "interface": "eth0",
        "hub_url": "http://hub.example:8000",
        "send_interval_seconds": 5,
    }
    config["hub"]["api_key"] = "edge-api-secret"
    write_config(config, config_path)
    checks = tuple(
        HealthCheck(name, HealthStatus.WARNING if name == "hub_api" else HealthStatus.OK, "unavailable")
        for name in ("configuration", "edge_service", "edge_storage", "edge_buffer", "hub_api")
    )
    _mock_installer_environment(
        monkeypatch,
        config_path=config_path,
        health_reports=[HealthReport(checks, HealthStatus.DEGRADED, "edge")],
    )
    monkeypatch.setattr(cli, "_available_interfaces", lambda: ["eth0"])
    times = iter((0.0, 31.0))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(times))

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    output = capsys.readouterr()
    assert result == 1
    assert "ROCKS READY" not in output.out
    assert "hub_api" in output.err


def test_installer_reports_service_verification_failure_and_stops_units(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_hub_config(tmp_path / "hub.db"), config_path)
    commands = _mock_installer_environment(monkeypatch, config_path=config_path)

    class FailedServiceManager:
        def __init__(self, **_kwargs):
            self.systemd_check = lambda: True

        def status(self):
            return []

        def verify(self):
            raise cli.ServiceManagerError("rocks-hub.service is not running (state: failed/failed).")

    monkeypatch.setattr(cli, "ServiceManager", FailedServiceManager)
    times = iter((0.0, 1.0, 31.0))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(times))

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    captured = capsys.readouterr()
    assert result == 1
    assert "ROCKS READY" not in captured.out
    assert "INSTALLATION FAILED" in captured.err
    assert "rocks-hub.service is not running" in captured.err
    assert commands[-1][1:5] == ["-n", "systemctl", "stop", "rocks-hub.service"]


def test_installer_does_not_stop_previously_active_unit_on_failed_rerun(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_hub_config(tmp_path / "hub.db"), config_path)
    commands = _mock_installer_environment(monkeypatch, config_path=config_path)

    class PreviouslyActiveManager:
        def __init__(self, **_kwargs):
            self.systemd_check = lambda: True

        def status(self):
            return [("rocks-hub.service", "active", "enabled")]

        def verify(self):
            raise cli.ServiceManagerError("rocks-hub.service is not running (state: failed/failed).")

    monkeypatch.setattr(cli, "ServiceManager", PreviouslyActiveManager)
    times = iter((0.0, 31.0))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(times))

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    captured = capsys.readouterr()
    assert result == 1
    assert "INSTALLATION FAILED" in captured.err
    assert not any("systemctl" in command and "stop" in command for command in commands)


def test_installer_rejects_mode_mismatch_without_overwriting_config(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_hub_config(tmp_path / "hub.db"), config_path)
    original = config_path.read_bytes()
    _mock_installer_environment(monkeypatch, config_path=config_path)

    result = main(["install", "--config-path", str(config_path), "--mode", "edge", "--non-interactive"])

    assert result == 2
    assert config_path.read_bytes() == original
    assert "pass --force" in capsys.readouterr().err


def test_installer_fails_before_start_when_shared_listener_port_is_taken(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_hub_config(tmp_path / "hub.db"), config_path)
    unhealthy_checks = tuple(
        HealthCheck(name, HealthStatus.ERROR if name in {"hub_service", "hub_api"} else HealthStatus.OK, "check")
        for name in ("configuration", "hub_service", "hub_database", "hub_api", "dashboard")
    )
    report = HealthReport(unhealthy_checks, HealthStatus.UNHEALTHY, "hub")
    commands = _mock_installer_environment(monkeypatch, config_path=config_path, health_reports=[report])
    monkeypatch.setattr(cli, "listener_port_available", lambda _host, _port: False)

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    captured = capsys.readouterr()
    assert result == 1
    assert "Failed component: Hub/Dashboard port" in captured.err
    assert "already in use" in captured.err
    assert not commands


def test_installer_refuses_root_execution(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "detect_platform", lambda: "linux")
    monkeypatch.setattr(cli, "python_version_supported", lambda: True)

    result = main(["install", "--config-path", str(tmp_path / "missing.yaml"), "--non-interactive"])

    assert result == 2
    assert "normal account" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="the shell installer intentionally refuses root execution")
def test_shell_installer_creates_venv_installs_package_and_hands_off_to_guided_cli(tmp_path):
    repository = Path(__file__).resolve().parents[1]
    sandbox = tmp_path / "rocks sandbox with spaces"
    sandbox.mkdir()
    script = sandbox / "install-rocks.sh"
    shutil.copy2(repository / "install-rocks.sh", script)
    mock_bin = tmp_path / "mock-bin"
    mock_bin.mkdir()
    log = tmp_path / "mock.log"
    venv_python = tmp_path / "mock-venv-python"
    venv_python.write_text(
        "#!/bin/sh\nprintf 'venv-python %s\\n' \"$*\" >> \"$MOCK_LOG\"\nexit 0\n",
        encoding="utf-8",
    )
    rocks = tmp_path / "mock-rocks"
    rocks.write_text(
        "#!/bin/sh\nprintf 'rocks %s\\n' \"$*\" >> \"$MOCK_LOG\"\nexit 0\n",
        encoding="utf-8",
    )
    python3 = mock_bin / "python3"
    python3.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            printf 'python3 %s\\n' "$*" >> "$MOCK_LOG"
            if [ "$1" = "-" ]; then cat >/dev/null; exit 0; fi
            if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
              mkdir -p "$3/bin"
              cp "$MOCK_VENV_PYTHON" "$3/bin/python"
              cp "$MOCK_ROCKS" "$3/bin/rocks"
              chmod +x "$3/bin/python" "$3/bin/rocks"
              exit 0
            fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    systemctl = mock_bin / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >> \"$MOCK_LOG\"\nexit 0\n",
        encoding="utf-8",
    )
    sudo = mock_bin / "sudo"
    sudo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for executable in (python3, systemctl, sudo, venv_python, rocks):
        executable.chmod(0o755)

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{mock_bin}:{environment['PATH']}",
            "MOCK_LOG": str(log),
            "MOCK_VENV_PYTHON": str(venv_python),
            "MOCK_ROCKS": str(rocks),
        }
    )
    result = subprocess.run(
        ["bash", str(script), "--mode", "hub"],
        cwd=sandbox,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (sandbox / ".venv" / "bin" / "python").is_file()
    calls = log.read_text(encoding="utf-8")
    assert "-m pip install -e" in calls
    assert "rocks install --mode hub" in calls
    assert "systemctl show-environment" in calls
    assert f"venv-python -m pip install -e {sandbox}" in calls


def test_install_help_lists_complete_install_controls(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["install", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--mode" in output
    assert "--config-path" in output
    assert "--non-interactive" in output
    assert "--dashboard-password" not in output


def test_repository_launcher_runs_cli_without_activation():
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [str(repository / "rocks"), "--version"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.startswith("ROCKS Fleet ")