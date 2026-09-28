from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

from rocks.edge.telemetry import TelemetryRecord
from rocks.ml.features import actual_traffic, behavior_summary_features

MODEL_VERSION = "rocks-baseline-v1"


@dataclass(frozen=True)
class AnalysisResult:
    telemetry_id: str
    sensor_id: str
    device_id: str | None
    timestamp: str
    model_version: str
    baseline_status: str
    actual_traffic: float
    expected_traffic: float | None
    deviation: float | None
    anomaly_score: float | None
    retention_score: float | None
    retention_priority: str | None
    analyzed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_behavior_summary(
    record: TelemetryRecord,
    *,
    expected_traffic: float | None,
    baseline_status: str,
    analyzed_at: str,
) -> AnalysisResult:
    actual = actual_traffic(record)
    if expected_traffic is None or baseline_status != "READY":
        return AnalysisResult(
            telemetry_id=record.record_id,
            sensor_id=record.sensor_id,
            device_id=record.device_id,
            timestamp=record.timestamp,
            model_version=MODEL_VERSION,
            baseline_status="BASELINE_NOT_READY",
            actual_traffic=actual,
            expected_traffic=None,
            deviation=None,
            anomaly_score=None,
            retention_score=None,
            retention_priority=None,
            analyzed_at=analyzed_at,
        )

    expected = max(0.0, float(expected_traffic))
    deviation = abs(actual - expected) / max(expected, 1e-9)
    anomaly_score = _bounded(1.0 - math.exp(-deviation))
    retention_score = anomaly_score
    return AnalysisResult(
        telemetry_id=record.record_id,
        sensor_id=record.sensor_id,
        device_id=record.device_id,
        timestamp=record.timestamp,
        model_version=MODEL_VERSION,
        baseline_status="READY",
        actual_traffic=actual,
        expected_traffic=expected,
        deviation=deviation,
        anomaly_score=anomaly_score,
        retention_score=retention_score,
        retention_priority=retention_priority(retention_score),
        analyzed_at=analyzed_at,
    )


def retention_priority(score: float | None) -> str | None:
    if score is None:
        return None
    value = _bounded(score)
    if value < 0.40:
        return "LOW"
    if value < 0.70:
        return "MEDIUM"
    return "HIGH"


def _bounded(value: float) -> float:
    if not math.isfinite(value):
        return 1.0 if value > 0 else 0.0
    return min(1.0, max(0.0, value))
