from __future__ import annotations

from typing import Any

from rocks.hub.storage import HubStorage
from rocks.ml.config import get_ml_config
from rocks.alerts.config import get_email_config
from rocks.health import HealthChecker, HealthStatus


class DashboardService:
    """Read-only dashboard view model backed by HubStorage."""

    def __init__(self, storage: HubStorage, ml_service: object | None = None) -> None:
        self.storage = storage
        self.ml_service = ml_service

    def summary(self) -> dict[str, Any]:
        edge_counts = self.storage.dashboard_edge_counts()
        fleet_counts = self.storage.dashboard_fleet_counts()
        ml_config = get_ml_config()
        model_status = {"status": "NOT_READY", "model_version": ml_config.model_version, "training_samples": 0, "last_trained": None}
        model = getattr(self.ml_service, "model", None)
        if model is not None:
            model_status = model.status_dict()
        analysis = self.storage.recent_analysis(100)
        return {
            "hub_status": "ONLINE",
            "edges": {**edge_counts, "offline": edge_counts["stale"] + edge_counts["unknown"]},
            "telemetry": {
                "total": fleet_counts["telemetry_total"],
                "recent": fleet_counts["telemetry_recent"],
                "recent_window_seconds": 300,
            },
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
            "storage": {"connected": True, "telemetry_records": fleet_counts["telemetry_total"], "analysis_records": self.storage.analysis_count()},
            "alerts": {
                "open": fleet_counts["open_alerts"],
                "high_critical": fleet_counts["high_critical_alerts"],
                "recent": fleet_counts["alerts_recent"],
                "recent_items": self.storage.dashboard_recent_alerts(limit=5),
            },
            "investigations": {"open": fleet_counts["open_investigations"]},
        }

    def edges(self) -> list[dict[str, Any]]:
        edges = self.storage.dashboard_edges()
        for edge in edges:
            if not edge.get("last_seen"):
                edge["status"] = "UNKNOWN"
            elif edge["status"] != "ONLINE":
                edge["status"] = "STALE"
        return edges

    def health(self) -> dict[str, Any]:
        try:
            report = HealthChecker().run()
        except Exception:
            return {
                "overall": "UNHEALTHY",
                "checks": [{"name": "diagnostics", "status": "DEGRADED", "message": "Health diagnostics are temporarily unavailable."}],
            }
        status_map = {
            HealthStatus.OK: "HEALTHY",
            HealthStatus.WARNING: "DEGRADED",
            HealthStatus.UNKNOWN: "DEGRADED",
            HealthStatus.ERROR: "UNHEALTHY",
            HealthStatus.NOT_APPLICABLE: "NOT_APPLICABLE",
        }
        visible_checks = {"configuration", "hub_api", "hub_database", "telemetry", "alerts", "edge_service", "hub_service", "dashboard"}
        return {
            "overall": report.overall.value,
            "checks": [
                {
                    "name": check.name,
                    "status": status_map.get(check.status, "DEGRADED"),
                    "message": check.message,
                }
                for check in report.checks
                if check.name in visible_checks
            ],
        }

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
            alert.pop("notification_error", None)
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
        notes = self.storage.investigation_notes(case_id) if case is not None else []
        actions = self.storage.investigation_actions(case_id) if case is not None else []
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
            "notes": notes or [],
            "actions": actions or [],
            "alerts": alerts,
            "device_found": device_found,
        }
