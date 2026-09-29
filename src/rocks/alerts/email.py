from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Any, Callable, Mapping

from rocks.alerts.config import EmailConfig
from rocks.alerts.engine import Alert
from rocks.edge.telemetry import TelemetryRecord


class NotificationError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class NotificationResult:
    status: str
    message: str


class EmailNotificationService:
    """Bounded SMTP sender for existing ROCKS alerts."""

    def __init__(
        self,
        config: EmailConfig,
        *,
        smtp_factory: Callable[..., Any] | None = None,
        smtp_ssl_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self.smtp_factory = smtp_factory or smtplib.SMTP
        self.smtp_ssl_factory = smtp_ssl_factory or smtplib.SMTP_SSL

    def is_enabled(self) -> bool:
        return self.config.enabled

    def should_notify(self, alert: Alert) -> bool:
        if not self.config.enabled:
            return False
        severity_rank = {"WARNING": 1, "HIGH": 2}
        minimum = severity_rank.get(self.config.minimum_severity.upper())
        alert_rank = severity_rank.get(alert.severity.upper())
        if minimum is None:
            return False
        return alert_rank is not None and alert_rank >= minimum

    def send_alert(self, alert: Alert, telemetry: TelemetryRecord | None) -> None:
        message = self._message_for_alert(alert, telemetry)
        self._send(message)

    def send_test(self) -> NotificationResult:
        if not self.config.enabled:
            return NotificationResult("DISABLED", "Email notifications are disabled.")
        message = self._base_message()
        message["Subject"] = "[ROCKS] SMTP configuration test"
        message.set_content(
            "This is a manually requested ROCKS Fleet SMTP configuration test.\n"
            "No security alert was created."
        )
        self._send(message)
        return NotificationResult("SENT", "SMTP test message sent successfully.")

    def _message_for_alert(self, alert: Alert, telemetry: TelemetryRecord | None) -> EmailMessage:
        message = self._base_message()
        message["Subject"] = f"[ROCKS] Network Security Alert — {alert.severity}"
        payload = telemetry.payload if telemetry is not None else {}
        source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
        source_ip = source.get("ip") or payload.get("source_ip") or "Not available"
        event_type = telemetry.event_type if telemetry is not None else "Not available"
        device_id = alert.device_id or "Not available"
        anomaly_score = f"{alert.anomaly_score:.3f}" if alert.anomaly_score is not None else "Not available"
        retention = f"{alert.retention_score:.3f}" if alert.retention_score is not None else "Not available"
        lines = [
            "ROCKS Fleet Alert",
            "",
            f"Alert ID: {alert.alert_id}",
            f"Time: {alert.timestamp}",
            f"Sensor: {alert.sensor_id}",
            f"Device: {device_id}",
            f"Source IP: {source_ip}",
            f"Event Type: {event_type}",
            f"Risk: {alert.severity}",
            f"Anomaly Score: {anomaly_score}",
            f"Retention Score: {retention}",
            "",
            "Summary:",
            alert.message,
            "",
            "Investigation:",
            f"Open the ROCKS Command Center and inspect alert {alert.alert_id}.",
            f"Related telemetry route: /dashboard/telemetry/{alert.telemetry_id}",
        ]
        message.set_content("\n".join(lines))
        return message

    def _base_message(self) -> EmailMessage:
        host, port, sender, recipients = self._validated_settings()
        del host, port
        message = EmailMessage()
        message["From"] = sender
        message["To"] = ", ".join(recipients)
        return message

    def _validated_settings(self) -> tuple[str, int, str, list[str]]:
        host = self.config.smtp_host.strip()
        sender = self.config.sender.strip()
        if not host or any(character in host for character in "\r\n\x00"):
            raise NotificationError("smtp_configuration_invalid")
        if not 1 <= self.config.smtp_port <= 65535:
            raise NotificationError("smtp_configuration_invalid")
        if not 0 < self.config.timeout_seconds <= 30:
            raise NotificationError("smtp_configuration_invalid")
        if self.config.starttls and self.config.use_ssl:
            raise NotificationError("smtp_configuration_invalid")
        if self.config.username and not self.config.password:
            raise NotificationError("smtp_configuration_invalid")
        if self.config.password and not self.config.username:
            raise NotificationError("smtp_configuration_invalid")
        if self.config.username and not (self.config.starttls or self.config.use_ssl):
            raise NotificationError("smtp_configuration_invalid")
        if not sender or any(character in sender for character in "\r\n\x00"):
            raise NotificationError("smtp_configuration_invalid")
        sender_name, sender_address = parseaddr(sender)
        if not sender_address or "@" not in sender_address:
            raise NotificationError("smtp_configuration_invalid")
        recipient_pairs = getaddresses([self.config.recipients])
        recipients = [address for _, address in recipient_pairs if address and "@" in address]
        if not recipients or any(character in recipient for recipient in recipients for character in "\r\n\x00"):
            raise NotificationError("smtp_configuration_invalid")
        clean_sender = sender_address if not sender_name else f"{sender_name} <{sender_address}>"
        return host, self.config.smtp_port, clean_sender, recipients

    def _send(self, message: EmailMessage) -> None:
        host, port, _sender, recipients = self._validated_settings()
        try:
            if self.config.use_ssl:
                with self.smtp_ssl_factory(
                    host,
                    port,
                    timeout=self.config.timeout_seconds,
                    context=ssl.create_default_context(),
                ) as smtp:
                    self._deliver(smtp, message, recipients)
            else:
                with self.smtp_factory(host, port, timeout=self.config.timeout_seconds) as smtp:
                    if self.config.starttls:
                        smtp.ehlo()
                        smtp.starttls(context=ssl.create_default_context())
                        smtp.ehlo()
                    self._deliver(smtp, message, recipients)
        except (TimeoutError, smtplib.SMTPServerDisconnected) as exc:
            raise NotificationError("smtp_timeout") from exc
        except smtplib.SMTPAuthenticationError as exc:
            raise NotificationError("smtp_authentication_failed") from exc
        except (OSError, smtplib.SMTPException) as exc:
            raise NotificationError("smtp_delivery_failed") from exc

    def _deliver(self, smtp: Any, message: EmailMessage, recipients: list[str]) -> None:
        if self.config.username:
            smtp.login(self.config.username, self.config.password)
        refused = smtp.send_message(message, to_addrs=recipients)
        if isinstance(refused, Mapping) and refused:
            raise NotificationError("smtp_recipients_rejected")


def utc_notification_time() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
