from __future__ import annotations

import subprocess

import pytest

from rocks.cli import main
from rocks.config import write_config
from rocks.service_manager import (
    EDGE_UNIT,
    HUB_UNIT,
    ServiceManager,
    ServiceManagerError,
    deployment_units,
    render_units,
)


def _config(mode: str) -> dict:
    return {
        "deployment": {"mode": mode},
        "edge": {"sensor_id": "ROCKS-EDGE-01", "interface": "eth0"},
        "hub": {"api_key": "secret-edge-key"},
        "dashboard": {
            "admin_password_hash": "secret-password-hash",
            "session_secret": "secret-session-value",
        },
        "storage": {"hub_database": "data/rocks-hub.db"},
        "ml": {"model_path": "data/ml/rocks_baseline.joblib"},
    }


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("edge", (EDGE_UNIT,)),
        ("hub", (HUB_UNIT,)),
        ("all-in-one", (EDGE_UNIT, HUB_UNIT)),
    ],
)
def test_deployment_mode_selects_expected_units(mode, expected):
    assert deployment_units(_config(mode)) == expected


def test_edge_unit_uses_existing_python_and_config_without_secrets(tmp_path):
    root = tmp_path / "Project With Spaces"
    config_path = root / "config" / "config.yaml"
    units = render_units(
        _config("edge"),
        config_path=config_path,
        application_directory=root,
        python_executable=tmp_path / "venv path" / "bin" / "python",
        service_user="schooladmin",
    )
    edge = units[EDGE_UNIT]
    assert "User=schooladmin" in edge
    escaped_root = str(root).replace(" ", "\\x20")
    escaped_environment_path = str(root / ".env").replace(" ", "\\x20")
    assert f"WorkingDirectory={escaped_root}" in edge
    assert f'Environment=ROCKS_CONFIG_PATH="{config_path}"' in edge
    assert f"EnvironmentFile=-{escaped_environment_path}" in edge
    assert f'ExecStart="{tmp_path / "venv path" / "bin" / "python"}" -m rocks edge run' in edge
    assert "Restart=on-failure" in edge
    assert "StandardOutput=journal" in edge
    assert "CAP_NET_RAW" in edge
    assert "secret-edge-key" not in edge
    assert "secret-password-hash" not in edge
    assert "secret-session-value" not in edge


def test_hub_unit_starts_combined_dashboard_once():
    units = render_units(_config("hub"), service_user="admin")
    assert list(units) == [HUB_UNIT]
    unit = units[HUB_UNIT]
    assert "-m rocks dashboard run" in unit
    assert "rocks hub run" not in unit
    assert "CAP_NET_RAW" not in unit


def test_all_in_one_generates_edge_and_combined_hub(tmp_path):
    units = render_units(
        _config("all-in-one"),
        application_directory=tmp_path,
        service_user="admin",
    )
    assert set(units) == {EDGE_UNIT, HUB_UNIT}
    assert "-m rocks edge run" in units[EDGE_UNIT]
    assert "-m rocks dashboard run" in units[HUB_UNIT]


def test_cli_generate_writes_units_to_temporary_directory(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_config("all-in-one"), config_path)
    output_dir = tmp_path / "units"
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))

    result = main(["service", "generate", "--output-dir", str(output_dir)])

    assert result == 0
    assert (output_dir / EDGE_UNIT).is_file()
    assert (output_dir / HUB_UNIT).is_file()
    assert "Generated:" in capsys.readouterr().out


def test_service_status_fails_clearly_when_systemd_unavailable(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_config("edge"), config_path)
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))
    manager = ServiceManager(config_path=config_path, systemd_check=lambda: False)
    with pytest.raises(ServiceManagerError, match="systemd is unavailable"):
        manager.status()

    from rocks import cli

    monkeypatch.setattr(cli, "ServiceManager", lambda: manager)
    result = main(["service", "status"])
    assert result == 2
    assert "systemd is unavailable" in capsys.readouterr().err


def test_service_status_uses_machine_readable_systemctl_properties(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(_config("edge"), config_path)

    def runner(command, **_kwargs):
        assert command[:3] == ["systemctl", "show", "--no-page"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n",
            stderr="",
        )

    manager = ServiceManager(
        config_path=config_path,
        systemctl="systemctl",
        runner=runner,
        systemd_check=lambda: True,
    )
    assert manager.status() == [(EDGE_UNIT, "active", "enabled")]


def test_install_writes_and_enables_only_mode_units(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    unit_directory = tmp_path / "systemd"
    write_config(_config("hub"), config_path)
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("rocks.service_manager.os.geteuid", lambda: 0)
    manager = ServiceManager(
        config_path=config_path,
        unit_directory=unit_directory,
        systemctl="systemctl",
        runner=runner,
        systemd_check=lambda: True,
    )

    installed = manager.install()

    assert installed == [HUB_UNIT]
    assert (unit_directory / HUB_UNIT).is_file()
    assert not (unit_directory / EDGE_UNIT).exists()
    assert [tuple(call[1:]) for call in calls] == [
        ("disable", "--now", EDGE_UNIT),
        ("daemon-reload",),
        ("enable", "--now", HUB_UNIT),
    ]


def test_install_requires_explicit_administrator_privileges(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    write_config(_config("edge"), config_path)
    monkeypatch.setattr("rocks.service_manager.os.geteuid", lambda: 1000)
    manager = ServiceManager(config_path=config_path, systemd_check=lambda: True)
    with pytest.raises(ServiceManagerError, match="requires administrator privileges"):
        manager.install()


def test_service_management_rejects_insecure_config(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("deployment:\n  mode: edge\n", encoding="utf-8")
    config_path.chmod(0o644)
    manager = ServiceManager(config_path=config_path, systemd_check=lambda: True)
    with pytest.raises(ServiceManagerError, match="chmod 600"):
        manager._load_config()


def test_service_help_lists_management_commands(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["service", "--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    for command in ("install", "uninstall", "status", "start", "stop", "restart", "generate"):
        assert command in output