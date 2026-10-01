from __future__ import annotations

import socket
import stat
from pathlib import Path

import pytest

from rocks import __version__
from rocks.cli import build_parser, main
from rocks.config import load_config
from rocks.paths import config_dir, data_dir, log_dir, project_root


def test_package_import():
    assert __version__ == "0.1.0"


def test_version_constant():
    assert __version__ == "0.1.0"


def test_cli_execution_status():
    exit_code = main(["status"])
    assert exit_code == 0


def test_cli_execution_version():
    exit_code = main(["--version"])
    assert exit_code == 0


def test_config_loading():
    config = load_config(Path("config/config.example.yaml"))
    assert config["project"]["name"] == "ROCKS Fleet"
    assert config["deployment"]["mode"] == "all-in-one"
    assert config["ml"]["enabled"] is False


def test_path_generation():
    root = project_root()
    assert root.name == "Project-RocksFleet"
    assert config_dir().is_dir()
    assert data_dir().name == "data"
    assert log_dir().name == "logs"


def test_parser_has_expected_commands():
    parser = build_parser()
    choices = [
        "status",
        "config",
        "logs",
        "test",
        "setup",
    ]
    assert all(choice in parser.format_help() for choice in choices)


def test_setup_writes_edge_configuration(tmp_path, capsys):
    config_path = tmp_path / "rocks-config.yaml"
    interface = socket.if_nameindex()[0][1]

    exit_code = main(
        [
            "setup",
            "--config-path",
            str(config_path),
            "--mode",
            "edge",
            "--sensor-id",
            "ROCKS-EDGE-SETUP",
            "--interface",
            interface,
            "--hub-url",
            "http://127.0.0.1:8000",
            "--api-key",
            "demo-api-key",
            "--non-interactive",
        ]
    )

    assert exit_code == 0
    config = load_config(config_path)
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert "demo-api-key" not in capsys.readouterr().out
    assert config["deployment"]["mode"] == "edge"
    assert config["edge"]["sensor_id"] == "ROCKS-EDGE-SETUP"
    assert config["edge"]["hub_url"] == "http://127.0.0.1:8000"
    assert config["hub"]["api_key"] == "demo-api-key"
