from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from rocks.edge.telemetry import TelemetryRecord
from rocks.hub.storage import HubStorage
from rocks.ml.analysis import AnalysisResult, MODEL_VERSION, analyze_behavior_summary
from rocks.ml.baseline import BaselineModel


class MLService:
    def __init__(
        self,
        storage: HubStorage,
        model_path: str | Path,
        minimum_samples: int = 20,
        model_version: str = MODEL_VERSION,
    ) -> None:
        self.storage = storage
        self.model = BaselineModel.load(
            model_path,
            minimum_samples=minimum_samples,
            model_version=model_version,
        )

    def train(self) -> int:
        records = self.storage.query_telemetry(event_type="BEHAVIOR_SUMMARY", limit=100000)
        count = self.model.train(records)
        if count >= self.model.minimum_samples:
            self.model.save()
        return count

    def analyze(self, record: TelemetryRecord) -> AnalysisResult | None:
        if record.event_type != "BEHAVIOR_SUMMARY":
            return None
        return analyze_behavior_summary(
            record,
            expected_traffic=self.model.expected_traffic(record),
            baseline_status=self.model.status.value,
            analyzed_at=_utc_now(),
        )

    def analyze_and_store(self, record: TelemetryRecord) -> AnalysisResult | None:
        result = self.analyze(record)
        if result is not None:
            self.storage.insert_analysis(result)
        return result

    def status(self) -> dict[str, object]:
        return self.model.status_dict()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
