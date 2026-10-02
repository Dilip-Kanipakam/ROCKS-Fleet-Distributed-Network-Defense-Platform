from __future__ import annotations

import socket
import stat
import sys

import pytest

from rocks.cli import main
from rocks.config import load_config
from rocks.dashboard.config import get_dashboard_config
from rocks.dashboard.auth import verify_password
from rocks.hub.config import get_hub_config


def test_edge_setup_validates_interface_and_keeps_api_key_private(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])

    result = main(
        [
            "setup", "--config-path", str(config_path), "--mode", "edge",
            "--sensor-id", "ROCKS-EDGE-01", "--interface", "eth-test",
            "--hub-url", "https://hub.example:8780", "--api-key", "private-key",
            "--non-interactive",
        ]
    )

    output = capsys.readouterr().out
    config = load_config(config_path)
    assert result == 0
    assert "private-key" not in output
    assert config["edge"]["interface"] == "eth-test"
    assert config["edge"]["send_interval_seconds"] > 0
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_edge_setup_rejects_unknown_interface(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])
    result = main(
        [
            "setup", "--config-path", str(tmp_path / "config.yaml"), "--mode", "edge",
            "--sensor-id", "ROCKS-EDGE-01", "--interface", "missing0",
            "--hub-url", "http://hub.example:8000", "--api-key", "private-key",
            "--non-interactive",
        ]
    )
    assert result == 2
    assert "interface" in capsys.readouterr().err.lower()


def test_hub_setup_runtime_uses_yaml_credentials_and_settings(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))
    result = main(
        [
            "setup", "--config-path", str(config_path), "--mode", "hub",
            "--dashboard-username", "administrator", "--dashboard-password", "long-password",
            "--hub-database", str(tmp_path / "hub.db"), "--non-interactive",
        ]
    )
    output = capsys.readouterr().out
    assert result == 0
    config = load_config(config_path)
    assert verify_password("long-password", config["dashboard"]["admin_password_hash"])
    assert config["dashboard"]["admin_password_hash"] != "long-password"
    dashboard = get_dashboard_config()
    hub = get_hub_config()
    assert dashboard.auth.username == "administrator"
    assert dashboard.auth.configured
    assert hub.database_path == tmp_path / "hub.db"
    assert "long-password" not in output
    assert config["ml"]["enabled"] is True
    assert config["alerts"]["enabled"] is True


def test_hub_setup_does_not_allow_missing_dashboard_password(tmp_path, capsys):
    result = main(
        [
            "setup", "--config-path", str(tmp_path / "config.yaml"), "--mode", "hub",
            "--dashboard-username", "administrator", "--non-interactive",
        ]
    )
    assert result == 2
    assert "password" in capsys.readouterr().err.lower()


def test_setup_preserves_unrelated_config_and_does_not_write_example(tmp_path, monkeypatch):
    from rocks import config as config_module

    generated_path = tmp_path / "config.yaml"
    example_path = tmp_path / "config.example.yaml"
    example_path.write_text("sentinel: unchanged\n", encoding="utf-8")
    monkeypatch.setattr(config_module, "DEFAULT_CONFIG_PATH", generated_path)
    monkeypatch.setattr(config_module, "DEFAULT_CONFIG_TEMPLATE_PATH", example_path)

    result = main(
        [
            "setup", "--mode", "edge", "--sensor-id", "ROCKS-EDGE-02",
            "--interface", socket.if_nameindex()[0][1], "--hub-url", "http://hub.example:8000",
            "--api-key", "private-key", "--non-interactive",
        ]
    )

    assert result == 0
    assert "sentinel: unchanged" == example_path.read_text(encoding="utf-8").strip()
    assert load_config(generated_path)["edge"]["sensor_id"] == "ROCKS-EDGE-02"


def test_setup_refuses_to_overwrite_tracked_example(capsys):
    from rocks.config import DEFAULT_CONFIG_TEMPLATE_PATH

    original = DEFAULT_CONFIG_TEMPLATE_PATH.read_bytes()
    result = main(
        [
            "setup", "--config-path", str(DEFAULT_CONFIG_TEMPLATE_PATH), "--mode", "edge",
            "--sensor-id", "ROCKS-EDGE-EXAMPLE", "--interface", socket.if_nameindex()[0][1],
            "--hub-url", "http://hub.example:8000", "--api-key", "private-key",
            "--force", "--non-interactive",
        ]
    )
    assert result == 2
    assert "read-only" in capsys.readouterr().err.lower()
    assert DEFAULT_CONFIG_TEMPLATE_PATH.read_bytes() == original


def test_setup_requires_force_before_noninteractive_overwrite(tmp_path, capsys):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("project:\n  local_setting: keep\n", encoding="utf-8")
    result = main(
        [
            "setup", "--config-path", str(config_path), "--mode", "edge",
            "--sensor-id", "ROCKS-EDGE-02", "--interface", socket.if_nameindex()[0][1],
            "--hub-url", "http://hub.example:8000", "--api-key", "private-key",
            "--non-interactive",
        ]
    )
    assert result == 2
    assert "--force" in capsys.readouterr().err
    assert "local_setting: keep" in config_path.read_text(encoding="utf-8")


def test_force_overwrite_preserves_unrelated_settings(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("project:\n  local_setting: keep\n", encoding="utf-8")
    result = main(
        [
            "setup", "--config-path", str(config_path), "--mode", "edge", "--force",
            "--sensor-id", "ROCKS-EDGE-02", "--interface", socket.if_nameindex()[0][1],
            "--hub-url", "http://hub.example:8000", "--api-key", "private-key",
            "--non-interactive",
        ]
    )
    assert result == 0
    assert load_config(config_path)["project"]["local_setting"] == "keep"


def test_all_in_one_registers_edge_key_and_does_not_print_it(tmp_path, monkeypatch, capsys):
    from rocks.hub.registry import EdgeRegistry
    from rocks.hub.storage import HubStorage

    config_path = tmp_path / "config.yaml"
    database_path = tmp_path / "hub.db"
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])
    result = main(
        [
            "setup", "--config-path", str(config_path), "--mode", "all-in-one",
            "--sensor-id", "ROCKS-EDGE-ALLINONE", "--interface", "eth-test",
            "--hub-url", "http://127.0.0.1:8000", "--dashboard-username", "admin",
            "--dashboard-password", "long-password", "--hub-database", str(database_path),
            "--non-interactive",
        ]
    )
    output = capsys.readouterr().out
    config = load_config(config_path)
    api_key = config["hub"]["api_key"]
    registry = EdgeRegistry(HubStorage(database_path))
    assert result == 0
    assert api_key
    assert registry.authenticate("ROCKS-EDGE-ALLINONE", api_key)
    assert api_key not in output
    assert "API key: configured" in output
    assert len(config["dashboard"]["session_secret"]) >= 40
    assert config["dashboard"]["session_secret"] not in output


def test_all_in_one_registers_supplied_api_key_as_hash(tmp_path, monkeypatch):
    from rocks.hub.registry import EdgeRegistry
    from rocks.hub.storage import HubStorage

    config_path = tmp_path / "config.yaml"
    database_path = tmp_path / "hub.db"
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])
    result = main(
        [
            "setup", "--config-path", str(config_path), "--mode", "all-in-one",
            "--sensor-id", "ROCKS-EDGE-KEY", "--interface", "eth-test",
            "--hub-url", "http://127.0.0.1:8000", "--api-key", "supplied-key",
            "--dashboard-username", "admin", "--dashboard-password", "long-password",
            "--hub-database", str(database_path), "--non-interactive",
        ]
    )
    config = load_config(config_path)
    storage = HubStorage(database_path)
    registry = EdgeRegistry(storage)
    assert result == 0
    assert config["hub"]["api_key"] == "supplied-key"
    assert registry.authenticate("ROCKS-EDGE-KEY", "supplied-key")
    assert storage.get_api_key_hash("ROCKS-EDGE-KEY") != "supplied-key"


def test_all_in_one_custom_hub_port_matches_dashboard_and_edge_url(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])

    result = main(
        [
            "setup", "--config-path", str(config_path), "--mode", "all-in-one",
            "--sensor-id", "ROCKS-EDGE-PORT", "--interface", "eth-test",
            "--hub-port", "8780", "--dashboard-username", "admin",
            "--dashboard-password", "long-password", "--hub-database", str(tmp_path / "hub.db"),
            "--non-interactive",
        ]
    )

    config = load_config(config_path)
    assert result == 0
    assert config["hub"]["port"] == 8780
    assert config["dashboard"]["port"] == 8780
    assert config["edge"]["hub_url"] == "http://127.0.0.1:8780"


def test_setup_rejects_different_shared_hub_and_dashboard_ports(tmp_path, capsys):
    from rocks.config import build_default_config, write_config

    config_path = tmp_path / "config.yaml"
    config = build_default_config()
    config["deployment"]["mode"] = "hub"
    config["hub"].update({"enabled": True, "port": 8080, "url": "http://127.0.0.1:8080"})
    config["dashboard"].update(
        {
            "enabled": True,
            "port": 8081,
            "admin_username": "admin",
            "admin_password_hash": "hash",
            "session_secret": "session-secret",
        }
    )
    write_config(config, config_path)

    result = main(["setup", "--config-path", str(config_path), "--check"])

    assert result == 2
    assert "share one listener" in capsys.readouterr().err


def test_setup_rejects_conflicting_explicit_port_arguments(tmp_path, capsys):
    result = main(
        [
            "setup", "--config-path", str(tmp_path / "config.yaml"), "--mode", "hub",
            "--hub-port", "8080", "--dashboard-port", "8081",
            "--dashboard-username", "admin", "--dashboard-password", "long-password",
            "--non-interactive",
        ]
    )

    assert result == 2
    assert "--hub-port and --dashboard-port must match" in capsys.readouterr().err


def test_interactive_setup_prompts_for_mode_and_selects_interface(tmp_path, monkeypatch, capsys):
    import builtins

    from rocks import cli

    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])
    answers = iter(["1", "ROCKS-EDGE-INTERACTIVE", "1", "http://hub.example:8000", "5"])
    monkeypatch.setattr(builtins, "input", lambda _prompt: next(answers))
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "interactive-key")

    result = main(["setup", "--config-path", str(config_path)])

    output = capsys.readouterr().out
    config = load_config(config_path)
    assert result == 0
    assert config["deployment"]["mode"] == "edge"
    assert config["edge"]["interface"] == "eth-test"
    assert config["hub"]["api_key"] == "interactive-key"
    assert "interactive-key" not in output


def test_setup_check_validates_without_mutating_config(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])
    assert main(
        [
            "setup", "--config-path", str(config_path), "--mode", "edge",
            "--sensor-id", "ROCKS-EDGE-CHECK", "--interface", "eth-test",
            "--hub-url", "http://hub.example:8000", "--api-key", "check-key",
            "--non-interactive",
        ]
    ) == 0
    original = config_path.read_bytes()
    assert main(["setup", "--config-path", str(config_path), "--check"]) == 0
    assert config_path.read_bytes() == original
    assert "check-key" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("hub_url", "send_interval"),
    [("file:///tmp/hub", "5"), ("http://hub.example:bad", "5"), ("http://hub.example:8000", "0")],
)
def test_setup_rejects_invalid_url_or_send_interval(tmp_path, monkeypatch, capsys, hub_url, send_interval):
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])
    result = main(
        [
            "setup", "--config-path", str(tmp_path / "config.yaml"), "--mode", "edge",
            "--sensor-id", "ROCKS-EDGE-01", "--interface", "eth-test",
            "--hub-url", hub_url, "--api-key", "private-key", "--send-interval", send_interval,
            "--non-interactive",
        ]
    )
    assert result == 2
    assert "setup error" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("bad_sensor", ["", "../sensor", "sensor/one", "x" * 66])
def test_setup_rejects_invalid_sensor_id(tmp_path, monkeypatch, bad_sensor, capsys):
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth-test")])
    result = main(
        [
            "setup", "--config-path", str(tmp_path / "config.yaml"), "--mode", "edge",
            "--sensor-id", bad_sensor, "--interface", "eth-test",
            "--hub-url", "http://hub.example:8000", "--api-key", "private-key",
            "--non-interactive",
        ]
    )
    assert result == 2
    assert "sensor" in capsys.readouterr().err.lower()