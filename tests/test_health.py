from __future__ import annotations

import sqlite3
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from rocks.cli import main
from rocks.config import write_config
from rocks.health import HealthChecker, HealthStatus, aggregate_health
from rocks.service_manager import EDGE_UNIT, HUB_UNIT


class FakeServiceManager:
    def __init__(self, statuses=None, error=None):
        self.statuses = statuses or []
        self.error = error

    def status(self):
        if self.error:
            raise self.error
        return self.statuses


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def _config(tmp_path, mode="all-in-one"):
    return {
        "project": {"name": "ROCKS Fleet", "version": "0.1.0"},
        "deployment": {"mode": mode},
        "edge": {
            "enabled": mode in {"edge", "all-in-one"},
            "sensor_id": "ROCKS-HEALTH-01",
            "interface": "eth-test",
            "hub_url": "http://hub.example:8000",
            "send_interval_seconds": 5,
        },
        "hub": {
            "enabled": mode in {"hub", "all-in-one"},
            "url": "http://hub.example:8000",
            "api_key": "SENSITIVE-API-KEY",
            "host": "127.0.0.1",
            "port": 8000,
        },
        "telemetry": {"interval_seconds": 60, "window_seconds": 60},
        "dashboard": {
            "enabled": mode in {"hub", "all-in-one"},
            "admin_username": "admin",
            "admin_password_hash": "SENSITIVE-PASSWORD-HASH",
            "session_secret": "SENSITIVE-SESSION-SECRET",
        },
        "storage": {
            "database": str(tmp_path / "edge.db"),
            "buffer": str(tmp_path / "buffer.db"),
            "hub_database": str(tmp_path / "hub.db"),
        },
        "alerts": {"enabled": True},
        "email": {"enabled": True, "username": "SMTP-PRIVATE-USER", "password": "SMTP-PRIVATE-PASSWORD"},
        "health": {"telemetry_freshness_seconds": 300},
    }


def _create_hub_db(path, *, telemetry_timestamp=None):
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE telemetry (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL);"
        "CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL);"
    )
    if telemetry_timestamp:
        connection.execute("INSERT INTO telemetry VALUES ('record-1', ?)", (telemetry_timestamp,))
    connection.commit()
    connection.close()


def _create_edge_db(path, *, telemetry_timestamp=None):
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE telemetry (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL)")
    if telemetry_timestamp:
        connection.execute("INSERT INTO telemetry VALUES ('record-1', ?)", (telemetry_timestamp,))
    connection.commit()
    connection.close()


def _create_buffer_db(path):
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE buffer (sequence INTEGER PRIMARY KEY, record_id TEXT)")
    connection.commit()
    connection.close()


def test_overall_health_aggregation_is_deterministic():
    assert aggregate_health([]) == HealthStatus.HEALTHY
    assert aggregate_health([HealthStatus.OK, HealthStatus.NOT_APPLICABLE]) == HealthStatus.HEALTHY
    assert aggregate_health([HealthStatus.UNKNOWN]) == HealthStatus.HEALTHY
    assert aggregate_health([HealthStatus.WARNING]) == HealthStatus.DEGRADED
    assert aggregate_health([HealthStatus.ERROR, HealthStatus.WARNING]) == HealthStatus.UNHEALTHY


def test_health_reports_running_services_and_fresh_telemetry(tmp_path):
    now = datetime.now(timezone.utc)
    hub_db = tmp_path / "hub.db"
    edge_db = tmp_path / "edge.db"
    _create_hub_db(hub_db, telemetry_timestamp=now.isoformat(timespec="seconds").replace("+00:00", "Z"))
    _create_edge_db(edge_db, telemetry_timestamp=now.isoformat(timespec="seconds").replace("+00:00", "Z"))
    _create_buffer_db(tmp_path / "buffer.db")
    config_path = tmp_path / "config.yaml"
    write_config(_config(tmp_path), config_path)
    manager = FakeServiceManager([(EDGE_UNIT, "active", "enabled"), (HUB_UNIT, "active", "enabled")])
    checker = HealthChecker(
        config_path=config_path,
        service_manager=manager,
        http_get=lambda _url, _timeout: FakeResponse(),
        now=lambda: now,
    )

    report = checker.run()

    assert report.overall == HealthStatus.HEALTHY
    assert report.get("configuration").status == HealthStatus.OK
    assert report.get("edge_service").status == HealthStatus.OK
    assert report.get("hub_service").status == HealthStatus.OK
    assert report.get("hub_database").status == HealthStatus.OK
    assert report.get("edge_storage").status == HealthStatus.OK
    assert report.get("hub_api").status == HealthStatus.OK
    assert report.get("dashboard").status == HealthStatus.OK
    assert report.get("telemetry").status == HealthStatus.OK


@pytest.mark.parametrize(
    ("active", "expected"),
    [("inactive", HealthStatus.WARNING), ("failed", HealthStatus.ERROR)],
)
def test_service_states_map_to_health_states(tmp_path, active, expected):
    config_path = tmp_path / "config.yaml"
    config = _config(tmp_path, "edge")
    write_config(config, config_path)
    checker = HealthChecker(
        config_path=config_path,
        service_manager=FakeServiceManager([(EDGE_UNIT, active, "disabled")]),
        http_get=lambda _url, _timeout: FakeResponse(),
    )
    report = checker.run()
    assert report.get("edge_service").status == expected


def test_systemd_unavailable_is_unknown_not_crash(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(_config(tmp_path, "edge"), config_path)
    checker = HealthChecker(
        config_path=config_path,
        service_manager=FakeServiceManager(error=RuntimeError("systemd unavailable")),
        http_get=lambda _url, _timeout: FakeResponse(),
    )
    report = checker.run()
    assert report.get("edge_service").status == HealthStatus.UNKNOWN


def test_unreachable_hub_is_warning_with_recovery_hint(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(_config(tmp_path, "edge"), config_path)

    def fail_get(_url, _timeout):
        raise urllib.error.URLError("offline")

    report = HealthChecker(
        config_path=config_path,
        service_manager=FakeServiceManager(error=RuntimeError("no systemd")),
        http_get=fail_get,
    ).run()
    assert report.get("hub_api").status == HealthStatus.WARNING
    assert "rocks edge test-hub" in report.get("hub_api").hint


def test_unavailable_database_is_error_and_read_only(tmp_path):
    config_path = tmp_path / "config.yaml"
    config = _config(tmp_path)
    config["storage"]["hub_database"] = str(tmp_path / "missing.db")
    write_config(config, config_path)
    report = HealthChecker(
        config_path=config_path,
        service_manager=FakeServiceManager(error=RuntimeError("no systemd")),
        http_get=lambda _url, _timeout: FakeResponse(),
    ).run()
    assert report.get("hub_database").status == HealthStatus.ERROR
    assert not (tmp_path / "missing.db").exists()


@pytest.mark.parametrize(
    ("timestamp", "expected", "message"),
    [
        (datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), HealthStatus.OK, "recent"),
        ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z"), HealthStatus.WARNING, "stale"),
        (None, HealthStatus.WARNING, "No telemetry"),
    ],
)
def test_telemetry_freshness_states(tmp_path, timestamp, expected, message):
    config_path = tmp_path / "config.yaml"
    config = _config(tmp_path, "hub")
    _create_hub_db(tmp_path / "hub.db", telemetry_timestamp=timestamp)
    write_config(config, config_path)
    report = HealthChecker(
        config_path=config_path,
        service_manager=FakeServiceManager([(HUB_UNIT, "active", "enabled")]),
        http_get=lambda _url, _timeout: FakeResponse(),
    ).run()
    assert report.get("telemetry").status == expected
    assert message.lower() in report.get("telemetry").message.lower()


def test_invalid_configuration_returns_configuration_error(tmp_path):
    config_path = tmp_path / "invalid.yaml"
    write_config({"deployment": {"mode": "unknown"}}, config_path)
    report = HealthChecker(config_path=config_path).run()
    assert report.get("configuration").status == HealthStatus.ERROR
    assert report.exit_code == 2


def test_malformed_yaml_is_reported_without_echoing_config_contents(tmp_path):
    config_path = tmp_path / "bad.yaml"
    config_path.write_text("secret: TOP-SECRET\ninvalid: [", encoding="utf-8")
    config_path.chmod(0o600)
    report = HealthChecker(config_path=config_path).run()
    assert report.get("configuration").status == HealthStatus.ERROR
    assert "TOP-SECRET" not in report.get("configuration").message


def test_world_readable_config_is_reported_as_invalid(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(_config(tmp_path, "edge"), config_path)
    config_path.chmod(0o644)
    report = HealthChecker(config_path=config_path).run()
    assert report.exit_code == 2
    assert "owner-only" in report.get("configuration").message


def test_health_output_never_displays_secrets(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))
    config = _config(tmp_path, "edge")
    config["edge"]["hub_url"] = "http://url-user:url-password@hub.example:8000/?token=URL-SECRET"
    _create_edge_db(tmp_path / "edge.db")
    write_config(config, config_path)
    monkeypatch.setattr(
        "rocks.cli.HealthChecker",
        lambda: HealthChecker(
            config_path=config_path,
            service_manager=FakeServiceManager(error=RuntimeError("no systemd")),
            http_get=lambda _url, _timeout: FakeResponse(),
        ),
    )
    result = main(["health", "verbose"])
    output = capsys.readouterr().out
    assert result == 1
    for secret in (
        "SENSITIVE-API-KEY",
        "SENSITIVE-PASSWORD-HASH",
        "SENSITIVE-SESSION-SECRET",
        "SMTP-PRIVATE-USER",
        "SMTP-PRIVATE-PASSWORD",
        "url-user",
        "url-password",
        "URL-SECRET",
    ):
        assert secret not in output
    assert "Deployment Mode" in output


def test_health_cli_exit_codes(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))
    write_config({"deployment": {"mode": "broken"}}, config_path)
    assert main(["health"]) == 2
    assert "Overall" in capsys.readouterr().out


def test_health_commands_are_registered():
    with pytest.raises(SystemExit) as exc_info:
        main(["health", "--help"])
    assert exc_info.value.code == 0