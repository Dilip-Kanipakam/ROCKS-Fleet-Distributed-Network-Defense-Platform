from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable

import joblib
from sklearn.ensemble import RandomForestRegressor

from rocks.edge.telemetry import TelemetryRecord
from rocks.ml.analysis import MODEL_VERSION
from rocks.ml.features import FEATURE_NAMES, behavior_summary_features


class BaselineStatus(str, Enum):
    NOT_READY = "NOT_READY"
    READY = "READY"


@dataclass
class BaselineModel:
    model_path: Path
    minimum_samples: int = 20
    model_version: str = MODEL_VERSION
    model: RandomForestRegressor | None = None
    training_samples: int = 0
    last_trained: str | None = None

    @property
    def status(self) -> BaselineStatus:
        return BaselineStatus.READY if self.model is not None else BaselineStatus.NOT_READY

    def train(self, records: Iterable[TelemetryRecord]) -> int:
        usable = [record for record in records if record.event_type == "BEHAVIOR_SUMMARY"]
        if len(usable) < self.minimum_samples:
            self.model = None
            self.training_samples = len(usable)
            self.last_trained = None
            return len(usable)
        x = [[features[name] for name in FEATURE_NAMES] for features in (behavior_summary_features(record) for record in usable)]
        y = [features["bytes_sent"] + features["bytes_received"] for features in (behavior_summary_features(record) for record in usable)]
        self.model = RandomForestRegressor(
            n_estimators=40,
            random_state=42,
            n_jobs=1,
            min_samples_leaf=1,
        )
        self.model.fit(x, y)
        self.training_samples = len(usable)
        self.last_trained = _utc_now()
        return len(usable)

    def expected_traffic(self, record: TelemetryRecord) -> float | None:
        if self.model is None:
            return None
        try:
            features = behavior_summary_features(record)
            prediction = float(self.model.predict([[features[name] for name in FEATURE_NAMES]])[0])
        except Exception:
            return None
        return max(0.0, prediction)

    def save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "model_version": self.model_version,
                "minimum_samples": self.minimum_samples,
                "training_samples": self.training_samples,
                "last_trained": self.last_trained,
            },
            self.model_path,
        )

    @classmethod
    def load(
        cls,
        model_path: str | Path,
        minimum_samples: int = 20,
        model_version: str = MODEL_VERSION,
    ) -> "BaselineModel":
        path = Path(model_path)
        if not path.exists():
            return cls(path, minimum_samples=minimum_samples, model_version=model_version)
        try:
            state = joblib.load(path)
        except Exception:
            return cls(path, minimum_samples=minimum_samples, model_version=model_version)
        if not isinstance(state, dict):
            return cls(path, minimum_samples=minimum_samples, model_version=model_version)
        model = state.get("model")
        if model is not None and not hasattr(model, "predict"):
            return cls(path, minimum_samples=minimum_samples, model_version=model_version)
        return cls(
            path,
            minimum_samples=int(state.get("minimum_samples", minimum_samples)),
            model_version=str(state.get("model_version", model_version)),
            model=model,
            training_samples=int(state.get("training_samples", 0)),
            last_trained=state.get("last_trained"),
        )

    def status_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "model_version": self.model_version,
            "training_samples": self.training_samples,
            "last_trained": self.last_trained,
            "model_path": str(self.model_path),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
