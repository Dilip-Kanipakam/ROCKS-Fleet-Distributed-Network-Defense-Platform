from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from rocks.alerts.engine import AlertEngine
from rocks.hub.storage import HubStorage
from rocks.ml.service import MLService
from rocks.simulator.generator import Scenario, generate_records


def run_demo() -> dict[str, object]:
    with TemporaryDirectory(prefix="rocks-demo-") as directory:
        storage = HubStorage(Path(directory) / "demo.db")
        baseline = generate_records(Scenario.NORMAL, count=20, sensor_id="ROCKS-DEMO-01")
        for record in baseline:
            storage.insert_telemetry(record)
        ml = MLService(storage, Path(directory) / "baseline.joblib", minimum_samples=20)
        samples = ml.train()
        engine = AlertEngine()
        normal = generate_records(Scenario.NORMAL, count=1, sensor_id="ROCKS-DEMO-01")[0]
        spike = generate_records(Scenario.HIGH_TRAFFIC, count=1, sensor_id="ROCKS-DEMO-01")[0]
        analyses = []
        alerts = []
        for record in (normal, spike):
            storage.insert_telemetry(record)
            analysis = ml.analyze_and_store(record)
            if analysis is not None:
                analyses.append(analysis)
                alert = engine.create_alert(analysis)
                if alert is not None:
                    storage.insert_alert(alert)
                    alerts.append(alert)
        return {
            "training_samples": samples,
            "model_status": ml.model.status.value,
            "normal_anomaly_score": analyses[0].anomaly_score,
            "spike_anomaly_score": analyses[1].anomaly_score,
            "alerts": len(alerts),
            "alert_counts": storage.alert_counts(),
        }
