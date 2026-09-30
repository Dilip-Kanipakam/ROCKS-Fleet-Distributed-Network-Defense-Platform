from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from rocks.detection.engine import DetectionAssessment
from rocks.edge.telemetry import TelemetryRecord
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
    created_at: str | None = None
    acknowledged_at: str | None = None
    resolved_at: str | None = None
    notification_status: str = "NOT_SENT"
    notification_sent_at: str | None = None
    notification_attempt_count: int = 0
    notification_error: str | None = None
    assessment: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AlertEngine:
    def __init__(self, *, anomaly_threshold: float = 0.70, high_retention_threshold: float = 0.70) -> None:
        self.anomaly_threshold = anomaly_threshold
        self.high_retention_threshold = high_retention_threshold

    def create_alert(
        self,
        analysis: AnalysisResult | None,
        *,
        assessment: DetectionAssessment | None = None,
        record: TelemetryRecord | None = None,
    ) -> Alert | None:
        anomaly = (analysis.anomaly_score if analysis else None) or 0.0
        retention = (analysis.retention_score if analysis else None) or 0.0
        ml_trigger = bool(
            analysis
            and (anomaly >= self.anomaly_threshold or retention >= self.high_retention_threshold or analysis.retention_priority == "HIGH")
        )
        if not ml_trigger and not (assessment and assessment.triggered):
            return None
        if assessment and assessment.triggered:
            severity = assessment.severity
        else:
            severity = "HIGH" if (analysis and (analysis.retention_priority == "HIGH" or anomaly >= self.anomaly_threshold)) else "WARNING"
        telemetry_id = analysis.telemetry_id if analysis else (assessment.telemetry_id if assessment else record.record_id)
        sensor_id = analysis.sensor_id if analysis else (assessment.sensor_id if assessment else record.sensor_id)
        device_id = analysis.device_id if analysis else (assessment.device_id if assessment else record.device_id)
        timestamp = analysis.timestamp if analysis else (assessment.timestamp if assessment else record.timestamp)
        reasons = assessment.reasons if assessment else []
        message = "; ".join(reasons[:3]) or "Behavior differs significantly from the learned traffic baseline."
        return Alert(
            alert_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"rocks:{telemetry_id}:POTENTIAL_ANOMALY")),
            timestamp=timestamp,
            telemetry_id=telemetry_id,
            sensor_id=sensor_id,
            device_id=device_id,
            alert_type="POTENTIAL_ANOMALY",
            severity=severity,
            anomaly_score=analysis.anomaly_score if analysis else None,
            retention_score=analysis.retention_score if analysis else None,
            message=message,
            status="OPEN",
            created_at=utc_now(),
            assessment=assessment.to_dict() if assessment else None,
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
