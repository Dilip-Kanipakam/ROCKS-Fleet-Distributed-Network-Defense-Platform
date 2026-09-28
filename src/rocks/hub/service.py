from __future__ import annotations

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
from rocks.alerts.config import get_alert_config


class HubService:
    def __init__(self, storage: HubStorage) -> None:
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
        try:
            record = telemetry_from_dict(data)
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
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
        if self.ml is not None:
            try:
                analysis = self.ml.analyze_and_store(record)
                if analysis is not None:
                    if self.alerts is not None:
                        alert = self.alerts.create_alert(analysis)
                        if alert is not None:
                            self.storage.insert_alert(alert)
            except Exception:
                self._logger.exception("Optional analysis or alerting failed for telemetry %s", record.record_id)
        return inserted

    def edges(self) -> list[EdgeInfo]:
        return self.registry.list()

    def stats(self) -> dict[str, Any]:
        edges = self.registry.list()
        return {
            "telemetry_records": self.storage.count(),
            "registered_edges": len(edges),
            "active_edges": sum(edge.status == "online" for edge in edges),
            "event_type_counts": self.storage.event_type_counts(),
        }
