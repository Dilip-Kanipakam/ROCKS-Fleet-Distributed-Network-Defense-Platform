from __future__ import annotations

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
    ]
    assert all(choice in parser.format_help() for choice in choices)
