from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import behavior_summary_telemetry
from rocks.ml.analysis import analyze_behavior_summary, retention_priority
from rocks.ml.baseline import BaselineModel, BaselineStatus
from rocks.ml.features import actual_traffic, behavior_summary_features


def make_record(timestamp: datetime, traffic: int, *, sensor_id: str = "ML-TEST"):
    features = TrafficFeatures(
           0, 60, 10, traffic, traffic // 2, traffic - traffic // 2, 0,
        4, 2, 3, 0, 2, 0, 0, 0, 0, traffic / 60, 10 / 60,
    )
    return behavior_summary_telemetry(features, sensor_id, timestamp=timestamp)


def training_records(count: int = 30):
    start = datetime(2026, 1, 5, 9, tzinfo=timezone.utc)
    return [make_record(start + timedelta(days=index), 1000 + (index % 2) * 20) for index in range(count)]


def test_behavior_summary_feature_extraction_and_actual_traffic():
    record = make_record(datetime(2026, 1, 5, 9, tzinfo=timezone.utc), 1000)
    features = behavior_summary_features(record)
    assert features["hour"] == 9
    assert features["day_of_week"] == 0
    assert actual_traffic(record) == 1000


def test_training_requires_minimum_samples(tmp_path):
    model = BaselineModel(tmp_path / "model.joblib", minimum_samples=20)
    assert model.train(training_records(19)) == 19
    assert model.status == BaselineStatus.NOT_READY
    assert model.expected_traffic(training_records(1)[0]) is None


def test_training_expected_traffic_and_save_load(tmp_path):
    path = tmp_path / "model.joblib"
    model = BaselineModel(path, minimum_samples=20)
    assert model.train(training_records()) == 30
    assert model.status == BaselineStatus.READY
    expected = model.expected_traffic(training_records(1)[0])
    assert expected is not None
    assert expected >= 0
    model.save()
    loaded = BaselineModel.load(path, minimum_samples=20)
    assert loaded.status == BaselineStatus.READY
    assert loaded.training_samples == 30
    assert loaded.expected_traffic(training_records(1)[0]) == expected


def test_normal_traffic_scores_lower_than_spike(tmp_path):
    records = training_records()
    model = BaselineModel(Path(tmp_path) / "model.joblib", minimum_samples=20)
    model.train(records)
    normal = records[-1]
    spike = make_record(datetime(2026, 2, 9, 9, tzinfo=timezone.utc), 20_000)
    normal_result = analyze_behavior_summary(normal, expected_traffic=model.expected_traffic(normal), baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    spike_result = analyze_behavior_summary(spike, expected_traffic=model.expected_traffic(spike), baseline_status="READY", analyzed_at="2026-01-01T00:00:00Z")
    assert 0 <= normal_result.anomaly_score <= 1
    assert 0 <= spike_result.anomaly_score <= 1
    assert spike_result.anomaly_score > normal_result.anomaly_score
    assert spike_result.retention_priority in {"MEDIUM", "HIGH"}


def test_not_ready_analysis_has_no_invented_score():
    record = make_record(datetime(2026, 1, 5, 3, tzinfo=timezone.utc), 100)
    result = analyze_behavior_summary(record, expected_traffic=None, baseline_status="NOT_READY", analyzed_at="2026-01-01T00:00:00Z")
    assert result.baseline_status == "BASELINE_NOT_READY"
    assert result.anomaly_score is None
    assert result.retention_score is None


def test_retention_priority_boundaries():
    assert retention_priority(0.0) == "LOW"
    assert retention_priority(0.39) == "LOW"
    assert retention_priority(0.4) == "MEDIUM"
    assert retention_priority(0.69) == "MEDIUM"
    assert retention_priority(0.7) == "HIGH"
