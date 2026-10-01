from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from rocks import cli
from rocks.cli import main
from rocks.config import write_config
from rocks.health import HealthCheck, HealthReport, HealthStatus
from rocks.installer import (
    dashboard_url,
    detect_platform,
    interface_choice,
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


def _mock_installer_environment(monkeypatch, *, config_path: Path, health_reports=None):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "detect_platform", lambda: "linux")
    monkeypatch.setattr(cli, "python_version_supported", lambda: True)

    class MockServiceManager:
        def __init__(self, **_kwargs):
            self.systemd_check = lambda: True

    monkeypatch.setattr(cli, "ServiceManager", MockServiceManager)
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
    assert "password-hash-never-print" not in output
    assert "session-secret-never-print" not in output


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


def test_installer_does_not_report_ready_when_required_health_fails(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_hub_config(tmp_path / "hub.db"), config_path)
    unhealthy_checks = tuple(
        HealthCheck(name, HealthStatus.ERROR if name == "hub_api" else HealthStatus.OK, "check")
        for name in ("configuration", "hub_service", "hub_database", "hub_api", "dashboard")
    )
    report = HealthReport(unhealthy_checks, HealthStatus.UNHEALTHY, "hub")
    _mock_installer_environment(monkeypatch, config_path=config_path, health_reports=[report])
    times = iter((0.0, 31.0))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(times))

    result = main(["install", "--config-path", str(config_path), "--non-interactive"])

    captured = capsys.readouterr()
    assert result == 1
    assert "ROCKS READY" not in captured.out
    assert "health checks did not pass" in captured.err


def test_installer_rejects_mode_mismatch_without_overwriting_config(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_hub_config(tmp_path / "hub.db"), config_path)
    original = config_path.read_bytes()
    _mock_installer_environment(monkeypatch, config_path=config_path)

    result = main(["install", "--config-path", str(config_path), "--mode", "edge", "--non-interactive"])

    assert result == 2
    assert config_path.read_bytes() == original
    assert "pass --force" in capsys.readouterr().err


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


def test_install_help_lists_complete_install_controls(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["install", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--mode" in output
    assert "--config-path" in output
    assert "--non-interactive" in output
    assert "--dashboard-password" not in output