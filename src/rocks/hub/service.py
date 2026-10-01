from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from rocks import __version__
from rocks.edge.telemetry import EVENT_TYPES, TelemetryRecord, telemetry_from_dict
from rocks.hub.models import EdgeInfo
from rocks.hub.registry import EdgeRegistry
from rocks.hub.storage import HubStorage
from rocks.logging_config import configure_logging
from rocks.ml.config import get_ml_config
from rocks.ml.service import MLService
from rocks.alerts.engine import AlertEngine
from rocks.alerts.config import get_alert_config, get_email_config
from rocks.alerts.email import EmailNotificationService, NotificationError
from rocks.detection.config import get_detection_config
from rocks.detection.engine import DetectionEngine

_SENSITIVE_TELEMETRY_KEY = re.compile(
    r"password|passwd|smtp|api.?key|token|cookie|authorization|session.?secret|credential|raw.?payload|packet.?payload|packet.?data|frame.?data",
    re.IGNORECASE,
)


class HubService:
    def __init__(self, storage: HubStorage, email_notifications: EmailNotificationService | None = None) -> None:
        self.storage = storage
        self.registry = EdgeRegistry(storage)
        self.storage.initialize()
        ml_config = get_ml_config()
        self.ml = MLService(
            storage,
            ml_config.model_path,
            ml_config.minimum_samples,
            ml_config.model_version,
        ) if ml_config.enabled else None
        self._logger = configure_logging()
        self.email_notifications = email_notifications or EmailNotificationService(get_email_config())
        self.detection = DetectionEngine(get_detection_config())
        alert_config = get_alert_config()
        self.alerts = AlertEngine(
            anomaly_threshold=alert_config.anomaly_threshold,
            high_retention_threshold=alert_config.high_retention_threshold,
        ) if alert_config.enabled else None

    def health(self) -> dict[str, Any]:
        self.storage.initialize()
        return {
            "status": "ok",
            "service": "rocks-hub",
            "version": __version__,
            "database_status": "ok",
            "registered_edge_count": len(self.registry.list()),
        }

    def validate_telemetry(self, data: dict[str, Any]) -> TelemetryRecord:
        allowed_fields = {
            "record_id", "schema_version", "timestamp", "sensor_id", "device_id",
            "event_type", "payload", "retention_priority", "retention_reason",
        }
        if not isinstance(data, dict) or set(data) - allowed_fields:
            raise ValueError("Telemetry contains unsupported fields")
        for field in ("schema_version", "timestamp", "sensor_id", "event_type"):
            if not isinstance(data.get(field), str):
                raise ValueError(f"Telemetry {field} must be text")
        if data.get("device_id") is not None and not isinstance(data.get("device_id"), str):
            raise ValueError("Telemetry device_id must be text or null")
        if not isinstance(data.get("payload"), dict):
            raise ValueError("Telemetry payload must be an object")
        supplied_record_id = data.get("record_id")
        if supplied_record_id is not None and (
            not isinstance(supplied_record_id, str)
            or len(supplied_record_id) > 128
            or any(ord(character) < 32 for character in supplied_record_id)
        ):
            raise ValueError("Invalid record_id")
        retention_priority = data.get("retention_priority")
        if retention_priority is not None and (
            isinstance(retention_priority, bool)
            or not isinstance(retention_priority, int)
            or not 0 <= retention_priority <= 100
        ):
            raise ValueError("Invalid retention_priority")
        retention_reason = data.get("retention_reason")
        if retention_reason is not None and (
            not isinstance(retention_reason, str) or len(retention_reason) > 500
        ):
            raise ValueError("Invalid retention_reason")
        try:
            record = telemetry_from_dict(data)
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", record.sensor_id):
            raise ValueError("Invalid sensor_id")
        if record.device_id is not None and (
            not isinstance(record.device_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,127}", record.device_id)
        ):
            raise ValueError("Invalid device_id")
        try:
            timestamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("timestamp requires a timezone")
            payload_json = json.dumps(record.payload, separators=(",", ":"), allow_nan=False)
        except (AttributeError, TypeError, ValueError, RecursionError) as exc:
            raise ValueError("Invalid timestamp or telemetry payload") from exc
        if len(payload_json.encode("utf-8")) > 32 * 1024:
            raise ValueError("Telemetry payload exceeds the 32 KiB limit")
        _validate_telemetry_payload_keys(record.payload)
        _validate_telemetry_payload_numbers(record.payload)
        if record.event_type not in EVENT_TYPES:
            raise ValueError("unsupported event_type")
        required_payloads = {
            "CONNECTION": ("source", "destination", "protocol"),
            "DNS": ("source_ip", "destination_ip", "request_count", "failure_count"),
            "RECONNECT": ("reconnect_count", "connection_failure_count"),
            "BEHAVIOR_SUMMARY": ("packet_count", "traffic_rate", "connection_count"),
        }
        missing = [field for field in required_payloads[record.event_type] if field not in record.payload]
        if missing:
            raise ValueError(f"Telemetry payload is missing required fields: {missing}")
        return record

    def ingest(self, record: TelemetryRecord) -> bool:
        inserted = self.storage.insert_telemetry(record)
        self.registry.touch(record.sensor_id)
        if inserted:
            try:
                analysis = self.ml.analyze(record) if self.ml is not None else None
                assessment = self.detection.assess(record, analysis)
                self.storage.insert_detection_assessment(assessment)
                if analysis is not None:
                    self.storage.insert_analysis(analysis)
                if self.alerts is not None:
                    alert = self.alerts.create_alert(analysis, assessment=assessment, record=record)
                    if alert is not None:
                        inserted_alert = self.storage.insert_alert(alert)
                        if inserted_alert and self.email_notifications.should_notify(alert):
                            self._notify_alert(alert, record)
            except Exception:
                self._logger.exception("Optional detection, analysis, or alerting failed for telemetry %s", record.record_id)
        return inserted

    def _notify_alert(self, alert: Any, record: TelemetryRecord) -> None:
        try:
            if not self.storage.claim_alert_notification(alert.alert_id):
                return
        except Exception as exc:
            self._logger.warning("Unable to claim alert email notification alert_id=%s reason=%s", alert.alert_id, type(exc).__name__)
            return

        try:
            self.email_notifications.send_alert(alert, record)
        except NotificationError as exc:
            self._finish_notification_failure(alert, exc.reason)
            return
        except Exception as exc:
            self._finish_notification_failure(alert, "notification_internal_error")
            self._logger.warning(
                "Alert email notification failed alert_id=%s reason=%s",
                alert.alert_id,
                type(exc).__name__,
            )
            return

        try:
            self.storage.finish_alert_notification(alert.alert_id, status="SENT")
        except Exception as exc:
            self._logger.warning("Unable to persist email notification result alert_id=%s reason=%s", alert.alert_id, type(exc).__name__)

    def _finish_notification_failure(self, alert: Any, reason: str) -> None:
        try:
            self.storage.finish_alert_notification(alert.alert_id, status="FAILED", error=reason)
        except Exception as exc:
            self._logger.warning("Unable to persist email notification failure alert_id=%s reason=%s", alert.alert_id, type(exc).__name__)
        self._logger.warning("Alert email notification failed alert_id=%s reason=%s", alert.alert_id, reason)

    def edges(self) -> list[EdgeInfo]:
        return self.registry.list()

    def stats(self) -> dict[str, Any]:
        edges = self.registry.list()
        return {
            "telemetry_records": self.storage.count(),
            "registered_edges": len(edges),
            "active_edges": sum(edge.status == "ONLINE" for edge in edges),
            "event_type_counts": self.storage.event_type_counts(),
        }


def _validate_telemetry_payload_keys(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("Telemetry payload nesting exceeds the 32-level limit")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or _SENSITIVE_TELEMETRY_KEY.search(key):
                raise ValueError("Telemetry payload contains a sensitive or unsupported field")
            _validate_telemetry_payload_keys(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_telemetry_payload_keys(child, depth=depth + 1)


def _validate_telemetry_payload_numbers(value: Any, *, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _validate_telemetry_payload_numbers(child, path=path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_telemetry_payload_numbers(child, path=path + (str(index),))
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < 0:
            field_path = ".".join(path) if path else "root"
            raise ValueError(f"Telemetry payload contains a negative value at {field_path}")
