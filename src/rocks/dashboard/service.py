from __future__ import annotations

from typing import Any

from rocks.hub.storage import HubStorage
from rocks.ml.config import get_ml_config
from rocks.alerts.config import get_email_config


class DashboardService:
    """Read-only dashboard view model backed by HubStorage."""

    def __init__(self, storage: HubStorage, ml_service: object | None = None) -> None:
        self.storage = storage
        self.ml_service = ml_service

    def summary(self) -> dict[str, Any]:
        edges = self.storage.dashboard_edges()
        ml_config = get_ml_config()
        model_status = {"status": "NOT_READY", "model_version": ml_config.model_version, "training_samples": 0, "last_trained": None}
        model = getattr(self.ml_service, "model", None)
        if model is not None:
            model_status = model.status_dict()
        analysis = self.storage.recent_analysis(100)
        return {
            "hub_status": "ONLINE",
            "edges": {
                "total": len(edges),
                "online": sum(edge["status"] == "ONLINE" for edge in edges),
                "offline": sum(edge["status"] == "OFFLINE" for edge in edges),
            },
            "telemetry": {"total": self.storage.count(), "recent": self.storage.recent_count()},
            "ml": {
                "status": model_status.get("status", "NOT_READY"),
                "training_samples": model_status.get("training_samples", 0),
                "model_version": model_status.get("model_version", ml_config.model_version),
                "last_trained": model_status.get("last_trained"),
                "minimum_samples": ml_config.minimum_samples,
            },
            "anomalies": {
                "recent": sum((item["anomaly_score"] or 0) >= 0.4 for item in analysis),
                "high_retention": sum(item["retention_priority"] == "HIGH" for item in analysis),
            },
            "storage": {"connected": True, "telemetry_records": self.storage.count(), "analysis_records": self.storage.analysis_count()},
            "alerts": self.storage.alert_counts(),
        }

    def edges(self) -> list[dict[str, Any]]:
        return self.storage.dashboard_edges()

    def telemetry(self, limit: int = 50, event_type: str | None = None, sensor_id: str | None = None) -> list[dict[str, Any]]:
        return self.storage.dashboard_telemetry(limit=limit, event_type=event_type, sensor_id=sensor_id)

    def telemetry_context(self, telemetry_id: str, limit: int = 50) -> dict[str, Any]:
        return self.storage.telemetry_context(telemetry_id=telemetry_id, limit=limit)

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        assessments = self.storage.recent_detection_assessments(limit)
        return assessments if assessments else self.storage.recent_analysis(limit)

    def traffic(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.storage.traffic_points(limit)

    def alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        alerts = self.storage.recent_alerts(limit)
        email_enabled = get_email_config().enabled
        for alert in alerts:
            status = alert.get("notification_status", "NOT_SENT")
            if status == "SENT":
                label = "Sent"
            elif status == "FAILED":
                label = "Failed"
            else:
                label = "Not sent" if email_enabled else "Not configured"
            alert["notification_label"] = label
        return alerts

    def investigation(self, device_id: str, start: str, end: str, *, sensor_id: str | None = None, case_id: str | None = None) -> dict[str, Any]:
        evidence = self.storage.investigation_timeline(
            device_id=device_id, start=start, end=end, sensor_id=sensor_id
        )
        cases = self.storage.investigations_for_device(device_id, sensor_id=sensor_id)
        alerts = self.storage.investigation_alerts_for_device(device_id, sensor_id=sensor_id)
        device_found = self.storage.investigation_device_exists(device_id)
        case = next((item for item in cases if item["investigation_id"] == case_id), None)
        case_events = self.storage.investigation_events(case_id) if case is not None else []
        timeline = list(evidence)
        for event in case_events or []:
            timeline.append(
                {
                    "timestamp": event["timestamp"],
                    "event_type": event["event_type"],
                    "device_id": device_id,
                    "sensor_id": sensor_id,
                    "severity": event["severity"],
                    "title": event["message"],
                    "reason": event["source"],
                    "reference_id": event["event_id"],
                    "details": event["metadata"],
                    "case_event": True,
                }
            )
        for event in timeline:
            details = event.get("details")
            if isinstance(details, dict) and event.get("event_type") in {"TELEMETRY", "BEHAVIOR_SUMMARY"}:
                byte_values = [details.get("bytes_sent"), details.get("bytes_received")]
                known_values = [value for value in byte_values if isinstance(value, (int, float))]
                if known_values:
                    details["bytes"] = sum(known_values)
        timeline.sort(key=lambda event: event["timestamp"])
        return {
            "device_id": device_id,
            "sensor_id": sensor_id,
            "start": start,
            "end": end,
            "timeline": timeline,
            "cases": cases,
            "selected_case": case,
            "alerts": alerts,
            "device_found": device_found,
        }
