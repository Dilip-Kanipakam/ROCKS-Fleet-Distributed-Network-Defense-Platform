from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.ml.analysis import analyze_behavior_summary
from rocks.ml.baseline import BaselineModel


def synthetic_records(count: int = 24) -> list:
    records = []
    start = datetime(2026, 1, 5, 9, tzinfo=timezone.utc)
    for index in range(count):
        timestamp = start + timedelta(hours=index)
        traffic = 1000 + (index % 3) * 50
        features = TrafficFeatures(0, 60, 10, traffic // 2, traffic // 2, 0, 4, 2, 3, 0, 2, 0, 0, 0, 0, traffic / 60, 10 / 60)
        records.append(behavior_summary_telemetry(features, "ROCKS-ML-TEST", timestamp=timestamp))
    return records


def run_demo(model_path: str | Path = Path("data/ml/demo.joblib")) -> tuple[float, float]:
    records = synthetic_records()
    model = BaselineModel(Path(model_path), minimum_samples=20)
    model.train(records)
    normal = records[-1]
    spike_features = TrafficFeatures(0, 60, 10, 20_000, 20_000, 0, 4, 2, 3, 0, 2, 0, 0, 0, 0, 666.0, 0.16)
    spike = behavior_summary_telemetry(spike_features, "ROCKS-ML-TEST", timestamp=datetime(2026, 1, 6, 9, tzinfo=timezone.utc))
    normal_result = analyze_behavior_summary(normal, expected_traffic=model.expected_traffic(normal), baseline_status=model.status.value, analyzed_at="2026-01-06T00:00:00Z")
    spike_result = analyze_behavior_summary(spike, expected_traffic=model.expected_traffic(spike), baseline_status=model.status.value, analyzed_at="2026-01-06T00:00:00Z")
    return normal_result.anomaly_score or 0.0, spike_result.anomaly_score or 0.0
