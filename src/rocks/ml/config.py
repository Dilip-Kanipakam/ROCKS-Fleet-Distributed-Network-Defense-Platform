from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rocks.config import load_config


@dataclass(frozen=True)
class MLConfig:
    enabled: bool = False
    model_path: Path = Path("data/ml/rocks_baseline.joblib")
    minimum_samples: int = 20
    model_version: str = "rocks-baseline-v1"


def get_ml_config() -> MLConfig:
    config = load_config().get("ml", {})
    return MLConfig(
        enabled=bool(config.get("enabled", False)),
        model_path=Path(str(config.get("model_path", "data/ml/rocks_baseline.joblib"))).expanduser(),
        minimum_samples=max(1, int(config.get("minimum_samples", 20))),
        model_version=str(config.get("model_version", "rocks-baseline-v1")),
    )
