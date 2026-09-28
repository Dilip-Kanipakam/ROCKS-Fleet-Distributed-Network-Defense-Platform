from __future__ import annotations

from typing import Any

from rocks.hub.storage import HubStorage
from rocks.ml.config import get_ml_config


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
                "online": sum(edge["status"] == "online" for edge in edges),
                "offline": sum(edge["status"] != "online" for edge in edges),
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
        }

    def edges(self) -> list[dict[str, Any]]:
        return self.storage.dashboard_edges()

    def telemetry(self, limit: int = 50, event_type: str | None = None, sensor_id: str | None = None) -> list[dict[str, Any]]:
        return self.storage.dashboard_telemetry(limit=limit, event_type=event_type, sensor_id=sensor_id)

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.storage.recent_analysis(limit)

    def traffic(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.storage.traffic_points(limit)
