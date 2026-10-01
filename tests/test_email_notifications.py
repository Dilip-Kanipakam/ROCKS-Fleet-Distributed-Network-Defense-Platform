from __future__ import annotations

import smtplib
import sqlite3
import ssl
import io
import logging
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from rocks.alerts.config import EmailConfig
from rocks.alerts.email import EmailNotificationService, NotificationError
from rocks.alerts.engine import Alert, AlertEngine
from rocks.cli import main
from rocks.config import load_config, write_config
from rocks.dashboard.service import DashboardService
from rocks.dashboard.auth import hash_password
from rocks.hub.app import create_app
from rocks.hub.service import HubService
from rocks.hub.storage import HubStorage
from rocks.ml.analysis import analyze_behavior_summary
from rocks.simulator.generator import Scenario, generate_records


class FakeSMTP:
    def __init__(self, host, port, *, timeout, context=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.messages = []
        self.login_values = []
        self.started_tls = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def ehlo(self):
        return None

    def starttls(self, *, context):
        self.started_tls = True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def login(self, username, password):
        self.login_values.append((username, password))

    def send_message(self, message, *, to_addrs):
        self.messages.append((message, to_addrs))


def _email_config(**overrides):
    config = EmailConfig(
        enabled=True,
        smtp_host="smtp.example.test",
        smtp_port=587,
        username="smtp-user",
        password="SMTP-SUPER-SECRET",
        sender="ROCKS Fleet <rocks@example.test>",
        recipients="admin@example.test, oncall@example.test",
        minimum_severity="HIGH",
        starttls=True,
        timeout_seconds=3,
    )
    return replace(config, **overrides)


def _alert(severity="HIGH"):
    return Alert(
        alert_id="alert-existing-123",
        timestamp="2026-09-29T12:00:00Z",
        telemetry_id="telemetry-existing-456",
        sensor_id="ROCKS-EDGE-01",
        device_id="192.0.2.10|02:00:00:00:00:01",
        alert_type="POTENTIAL_ANOMALY",
        severity=severity,
        anomaly_score=0.91,
        retention_score=0.88,
        message="Behavior differs significantly from the learned traffic baseline.",
    )


def test_email_disabled_does_not_contact_smtp():
    def unexpected_smtp(*_args, **_kwargs):
        raise AssertionError("SMTP must not be contacted while email is disabled")

    service = EmailNotificationService(EmailConfig(), smtp_factory=unexpected_smtp)
    assert service.send_test().status == "DISABLED"
    assert not service.should_notify(_alert())


def test_missing_smtp_configuration_fails_safely():
    service = EmailNotificationService(EmailConfig(enabled=True))
    with pytest.raises(NotificationError, match="smtp_configuration_invalid") as exc_info:
        service.send_test()
    assert "SMTP-SUPER-SECRET" not in str(exc_info.value)


def test_authenticated_smtp_requires_tls():
    service = EmailNotificationService(_email_config(starttls=False, use_ssl=False))
    with pytest.raises(NotificationError, match="smtp_configuration_invalid"):
        service.send_test()


def test_successful_alert_email_uses_tls_and_contains_only_alert_context():
    smtp_instances = []

    def smtp_factory(*args, **kwargs):
        instance = FakeSMTP(*args, **kwargs)
        smtp_instances.append(instance)
        return instance

    service = EmailNotificationService(_email_config(), smtp_factory=smtp_factory)
    alert = replace(
        _alert(),
        assessment={
            "rules_triggered": [
                {
                    "rule_id": "HIGH_TRAFFIC",
                    "evidence": {"traffic_rate": 250, "threshold": 200},
                }
            ],
            "ml_anomaly": False,
            "simulation": False,
        },
    )
    from rocks.edge.telemetry import TelemetryRecord

    telemetry = TelemetryRecord(
        sensor_id=alert.sensor_id,
        device_id=alert.device_id,
        event_type="BEHAVIOR_SUMMARY",
        payload={"source_ip": "192.0.2.10", "packet_count": 4, "secret": "DO-NOT-INCLUDE"},
        timestamp=alert.timestamp,
    )

    service.send_alert(alert, telemetry)

    smtp = smtp_instances[0]
    message, recipients = smtp.messages[0]
    body = message.get_content()
    assert smtp.timeout == 3
    assert smtp.started_tls
    assert smtp.login_values == [("smtp-user", "SMTP-SUPER-SECRET")]
    assert recipients == ["admin@example.test", "oncall@example.test"]
    assert message["Subject"] == "[ROCKS] Network Security Alert — HIGH"
    assert alert.alert_id in body
    assert alert.telemetry_id in body
    assert "192.0.2.10" in body
    assert "BEHAVIOR_SUMMARY" in body
    assert "DO-NOT-INCLUDE" not in body
    assert "SMTP-SUPER-SECRET" not in body
    assert "traffic_rate=250" in body
    assert "/dashboard/telemetry/telemetry-existing-456" in body


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (TimeoutError("SMTP-SUPER-SECRET"), "smtp_timeout"),
        (smtplib.SMTPConnectError(421, b"SMTP-SUPER-SECRET"), "smtp_delivery_failed"),
        (smtplib.SMTPAuthenticationError(535, b"SMTP-SUPER-SECRET"), "smtp_authentication_failed"),
    ],
)
def test_smtp_errors_are_bounded_and_redacted(exception, expected):
    class FailingSMTP(FakeSMTP):
        def __enter__(self):
            raise exception

    service = EmailNotificationService(_email_config(), smtp_factory=FailingSMTP)
    with pytest.raises(NotificationError) as exc_info:
        service.send_test()
    assert exc_info.value.reason == expected
    assert "SMTP-SUPER-SECRET" not in str(exc_info.value)


def test_minimum_severity_policy_uses_existing_alert_values():
    service = EmailNotificationService(_email_config(minimum_severity="HIGH"))
    assert service.should_notify(_alert("HIGH"))
    assert not service.should_notify(_alert("WARNING"))
    warning_service = EmailNotificationService(_email_config(minimum_severity="WARNING"))
    assert warning_service.should_notify(_alert("WARNING"))


def test_email_config_repr_redacts_addresses_and_secrets():
    rendered = repr(_email_config())
    for private_value in ("smtp-user", "SMTP-SUPER-SECRET", "rocks@example.test", "admin@example.test"):
        assert private_value not in rendered
    assert "password='configured'" in rendered


def test_malformed_optional_smtp_config_does_not_break_hub_startup(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config = load_config("config/config.example.yaml")
    config["deployment"]["mode"] = "hub"
    config["hub"]["enabled"] = True
    config["dashboard"].update(
        {"enabled": True, "admin_username": "admin", "admin_password_hash": "hash", "session_secret": "session"}
    )
    config["email"].update(
        {
            "enabled": True,
            "smtp_host": "smtp.example.test",
            "smtp_port": "not-a-port",
            "from": "rocks@example.test",
            "to": "admin@example.test",
        }
    )
    write_config(config, config_path)
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))

    service = HubService(HubStorage(tmp_path / "hub.db"))

    assert service.email_notifications.is_enabled()
    with pytest.raises(NotificationError, match="smtp_configuration_invalid"):
        service.email_notifications.send_test()


def test_alert_storage_migration_and_single_atomic_notification_claim(tmp_path):
    database_path = tmp_path / "old-hub.db"
    connection = sqlite3.connect(database_path)
    connection.execute(
        """CREATE TABLE alerts (
            alert_id TEXT PRIMARY KEY, telemetry_id TEXT NOT NULL, sensor_id TEXT NOT NULL,
            device_id TEXT, timestamp TEXT NOT NULL, alert_type TEXT NOT NULL,
            severity TEXT NOT NULL, anomaly_score REAL, retention_score REAL,
            message TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
            acknowledged_at TEXT, resolved_at TEXT
        )"""
    )
    connection.commit()
    connection.close()
    storage = HubStorage(database_path)
    alert = _alert()
    assert storage.insert_alert(alert)
    assert storage.claim_alert_notification(alert.alert_id)
    assert not storage.claim_alert_notification(alert.alert_id)
    storage.finish_alert_notification(alert.alert_id, status="FAILED", error="smtp_timeout")
    current = storage.get_alert(alert.alert_id)
    assert current is not None
    assert current.status == "OPEN"
    assert current.notification_status == "FAILED"
    assert current.notification_attempt_count == 1
    assert current.notification_error == "smtp_timeout"
    assert current.notification_sent_at is None


def test_hub_ingest_sends_once_only_for_new_alert_and_preserves_on_failure(tmp_path):
    config = _email_config()
    smtp_calls = []

    class FailingSMTP(FakeSMTP):
        def send_message(self, *_args, **_kwargs):
            smtp_calls.append(1)
            raise TimeoutError("SMTP-SUPER-SECRET")

    notifications = EmailNotificationService(config, smtp_factory=FailingSMTP)
    storage = HubStorage(tmp_path / "hub.db")
    service = HubService(storage, email_notifications=notifications)
    captured_logs = io.StringIO()
    capture_handler = logging.StreamHandler(captured_logs)
    service._logger.addHandler(capture_handler)
    record = generate_records(Scenario.HIGH_TRAFFIC, count=1)[0]
    analysis = analyze_behavior_summary(
        record,
        expected_traffic=1000,
        baseline_status="READY",
        analyzed_at="2026-09-29T12:00:00Z",
    )

    class FixedML:
        def analyze(self, _record):
            return analysis

    service.ml = FixedML()
    assert service.ingest(record) is True
    assert service.ingest(record) is False
    alert_row = storage.recent_alerts()[0]
    alert = storage.get_alert(alert_row["alert_id"])
    assert alert is not None
    assert alert.status == "OPEN"
    assert alert.notification_status == "FAILED"
    assert alert.notification_attempt_count == 1
    assert alert.notification_error == "smtp_timeout"
    assert smtp_calls == [1]
    service._logger.removeHandler(capture_handler)
    assert "SMTP-SUPER-SECRET" not in captured_logs.getvalue()


def test_hub_ingest_success_notification_is_not_repeated_for_duplicate_alert(tmp_path):
    smtp_instances = []

    def smtp_factory(*args, **kwargs):
        instance = FakeSMTP(*args, **kwargs)
        smtp_instances.append(instance)
        return instance

    service = HubService(
        HubStorage(tmp_path / "hub.db"),
        email_notifications=EmailNotificationService(_email_config(), smtp_factory=smtp_factory),
    )
    record = generate_records(Scenario.HIGH_TRAFFIC, count=1)[0]
    analysis = analyze_behavior_summary(record, expected_traffic=1000, baseline_status="READY", analyzed_at="2026-09-29T12:00:00Z")

    class FixedML:
        def analyze(self, _record):
            return analysis

    service.ml = FixedML()
    service.ingest(record)
    service.ingest(record)
    assert len(smtp_instances) == 1
    row = service.storage.recent_alerts()[0]
    assert row["notification_status"] == "SENT"
    assert row["notification_attempt_count"] == 1


def test_email_test_cli_disabled_and_success(monkeypatch, capsys):
    from rocks import cli

    monkeypatch.setattr(cli, "get_email_config", lambda: EmailConfig())
    assert main(["alerts", "email-test"]) == 0
    assert "DISABLED" in capsys.readouterr().out

    class SuccessfulTest:
        def __init__(self, _config):
            pass

        def send_test(self):
            return type("Result", (), {"status": "SENT", "message": "SMTP test message sent successfully."})()

    monkeypatch.setattr(cli, "get_email_config", lambda: _email_config())
    monkeypatch.setattr(cli, "EmailNotificationService", SuccessfulTest)
    assert main(["alerts", "email-test"]) == 0
    assert "sent successfully" in capsys.readouterr().out


def test_email_test_cli_failure_does_not_print_transport_secret(monkeypatch, capsys):
    from rocks import cli

    class FailedTest:
        def __init__(self, _config):
            pass

        def send_test(self):
            raise NotificationError("smtp_timeout")

    monkeypatch.setattr(cli, "get_email_config", lambda: _email_config())
    monkeypatch.setattr(cli, "EmailNotificationService", FailedTest)
    assert main(["alerts", "email-test"]) == 1
    output = capsys.readouterr().err
    assert "smtp_timeout" in output
    assert "SMTP-SUPER-SECRET" not in output


def test_dashboard_exposes_only_notification_state(monkeypatch):
    from rocks.dashboard import service as dashboard_service

    class FakeStorage:
        def recent_alerts(self, _limit):
            return [
                {"alert_id": "sent", "notification_status": "SENT"},
                {"alert_id": "failed", "notification_status": "FAILED"},
                {"alert_id": "not-sent", "notification_status": "NOT_SENT"},
            ]

    monkeypatch.setattr(dashboard_service, "get_email_config", lambda: _email_config())
    view = DashboardService(FakeStorage()).alerts()
    assert [row["notification_label"] for row in view] == ["Sent", "Failed", "Not sent"]
    assert all("password" not in row for row in view)


def test_authenticated_dashboard_renders_notification_state_without_smtp_secrets(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config = load_config("config/config.example.yaml")
    config["deployment"]["mode"] = "hub"
    config["dashboard"].update(
        {"enabled": True, "admin_username": "admin", "admin_password_hash": hash_password("dashboard-pass"), "session_secret": "dashboard-session"}
    )
    config["hub"]["enabled"] = True
    config["email"].update(
        {
            "enabled": True,
            "smtp_host": "smtp.example.test",
            "username": "SMTP-PRIVATE-USER",
            "password": "SMTP-PRIVATE-PASSWORD",
            "from": "private-from@example.test",
            "to": "private-recipient@example.test",
        }
    )
    write_config(config, config_path)
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))
    client = TestClient(create_app(str(tmp_path / "dashboard.db")))
    client.post("/dashboard/login", data={"username": "admin", "password": "dashboard-pass"})
    storage = client.app.state.hub_service.storage
    record = generate_records(Scenario.HIGH_TRAFFIC, count=1)[0]
    storage.insert_telemetry(record)
    alert = _alert()
    alert = replace(alert, telemetry_id=record.record_id, sensor_id=record.sensor_id)
    storage.insert_alert(alert)
    assert storage.claim_alert_notification(alert.alert_id)
    storage.finish_alert_notification(alert.alert_id, status="SENT")

    response = client.get("/dashboard/alerts")

    assert response.status_code == 200
    assert "Email" in response.text
    assert "Sent" in response.text
    for private_value in ("SMTP-PRIVATE-USER", "SMTP-PRIVATE-PASSWORD", "private-from@example.test", "private-recipient@example.test"):
        assert private_value not in response.text