from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from rocks.ml.analysis import AnalysisResult


@dataclass(frozen=True)
class Alert:
    alert_id: str
    timestamp: str
    telemetry_id: str
    sensor_id: str
    device_id: str | None
    alert_type: str
    severity: str
    anomaly_score: float | None
    retention_score: float | None
    message: str
    status: str = "OPEN"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AlertEngine:
    def __init__(self, *, anomaly_threshold: float = 0.70, high_retention_threshold: float = 0.70) -> None:
        self.anomaly_threshold = anomaly_threshold
        self.high_retention_threshold = high_retention_threshold

    def create_alert(self, analysis: AnalysisResult) -> Alert | None:
        anomaly = analysis.anomaly_score or 0.0
        retention = analysis.retention_score or 0.0
        if anomaly < self.anomaly_threshold and retention < self.high_retention_threshold and analysis.retention_priority != "HIGH":
            return None
        severity = "HIGH" if analysis.retention_priority == "HIGH" or anomaly >= self.anomaly_threshold else "WARNING"
        return Alert(
            alert_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"rocks:{analysis.telemetry_id}:POTENTIAL_ANOMALY")),
            timestamp=analysis.timestamp,
            telemetry_id=analysis.telemetry_id,
            sensor_id=analysis.sensor_id,
            device_id=analysis.device_id,
            alert_type="POTENTIAL_ANOMALY",
            severity=severity,
            anomaly_score=analysis.anomaly_score,
            retention_score=analysis.retention_score,
            message="Behavior differs significantly from the learned traffic baseline.",
            status="OPEN",
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
