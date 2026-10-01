from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from rocks.alerts.engine import AlertEngine
from rocks.detection.engine import DetectionEngine
from rocks.hub.storage import HubStorage
from rocks.ml.service import MLService
from rocks.simulator.generator import Scenario, generate_records


class DemoMode(str, Enum):
    NORMAL = "normal"
    ANOMALY = "anomaly"
    FULL = "full"


DEMO_SCENARIO_ALIASES = {
    "normal": Scenario.NORMAL,
    "high_traffic": Scenario.HIGH_TRAFFIC,
    "high-traffic": Scenario.HIGH_TRAFFIC,
    "reconnaissance_like": Scenario.RECONNAISSANCE_LIKE,
    "reconnaissance-like": Scenario.RECONNAISSANCE_LIKE,
    "dns_anomaly": Scenario.DNS_ANOMALY,
    "dns-anomaly": Scenario.DNS_ANOMALY,
    "reconnect_storm": Scenario.RECONNECT_STORM,
    "reconnect-storm": Scenario.RECONNECT_STORM,
    "deauth_related_simulation": Scenario.DEAUTH_RELATED_SIMULATION,
    "deauth-related-simulation": Scenario.DEAUTH_RELATED_SIMULATION,
    "mixed_anomalous": Scenario.MIXED_ANOMALOUS,
    "mixed-anomalous": Scenario.MIXED_ANOMALOUS,
    "anomaly": Scenario.HIGH_TRAFFIC,
    "mixed": Scenario.MIXED_ANOMALOUS,
}


def normalize_demo_mode(value: DemoMode | str | None) -> DemoMode:
    if value is None:
        return DemoMode.FULL
    if isinstance(value, DemoMode):
        return value
    normalized = str(value).strip().lower().replace("-", "_")
    if normalized in {"normal", "healthy"}:
        return DemoMode.NORMAL
    if normalized in {"anomaly", "suspicious", "abnormal"}:
        return DemoMode.ANOMALY
    if normalized in {"full", "complete", "pipeline"}:
        return DemoMode.FULL
    raise ValueError(f"Unsupported demo mode: {value}. Choose normal, anomaly, or full.")


def normalize_demo_scenario(value: Scenario | str | None) -> Scenario | None:
    if value is None:
        return None
    if isinstance(value, Scenario):
        return value
    normalized = str(value).strip().lower().replace("-", "_")
    alias = DEMO_SCENARIO_ALIASES.get(normalized)
    if alias is None:
        raise ValueError(
            f"Unsupported demo scenario: {value}. Use one of: "
            + ", ".join(sorted({scenario.value for scenario in Scenario}))
        )
    return alias


def _demo_sequence(mode: DemoMode | str) -> list[Scenario]:
    mode_name = normalize_demo_mode(mode)
    if mode_name == DemoMode.NORMAL:
        return [Scenario.NORMAL]
    if mode_name == DemoMode.ANOMALY:
        return [
            Scenario.HIGH_TRAFFIC,
            Scenario.RECONNAISSANCE_LIKE,
            Scenario.DNS_ANOMALY,
            Scenario.RECONNECT_STORM,
            Scenario.DEAUTH_RELATED_SIMULATION,
        ]
    return [
        Scenario.NORMAL,
        Scenario.HIGH_TRAFFIC,
        Scenario.RECONNAISSANCE_LIKE,
        Scenario.DNS_ANOMALY,
        Scenario.RECONNECT_STORM,
        Scenario.DEAUTH_RELATED_SIMULATION,
        Scenario.MIXED_ANOMALOUS,
    ]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_demo_sequence(
    *,
    mode: DemoMode | str = DemoMode.FULL,
    scenario: Scenario | str | None = None,
    count: int = 1,
    sensor_id: str = "ROCKS-DEMO-01",
) -> dict[str, Any]:
    normalized_mode = normalize_demo_mode(mode)
    normalized_scenario = normalize_demo_scenario(scenario)
    scenarios = [normalized_scenario] if normalized_scenario is not None else _demo_sequence(normalized_mode)
    if count < 1:
        raise ValueError("count must be greater than zero")

    with TemporaryDirectory(prefix="rocks-demo-") as directory:
        storage = HubStorage(Path(directory) / "demo.db")
        baseline = generate_records(Scenario.NORMAL, count=max(6, count * 2), sensor_id=sensor_id)
        for record in baseline:
            storage.insert_telemetry(record)

        ml = MLService(storage, Path(directory) / "baseline.joblib", minimum_samples=max(6, count * 2))
        ml.train()

        engine = DetectionEngine()
        alert_engine = AlertEngine()
        telemetry_events: list[dict[str, Any]] = []
        alert_ids: list[str] = []
        investigation_id: str | None = None
        suspicious_entries: list[dict[str, Any]] = []

        for current_scenario in scenarios:
            records = generate_records(current_scenario, count=count, sensor_id=sensor_id)
            for record in records:
                storage.insert_telemetry(record)
                analysis = ml.analyze_and_store(record)
                assessment = engine.assess(record, analysis)
                alert = alert_engine.create_alert(analysis, assessment=assessment, record=record) if analysis is not None or assessment.triggered else None
                if alert is not None:
                    storage.insert_alert(alert)
                    alert_ids.append(alert.alert_id)
                telemetry_entry = {
                    "record_id": record.record_id,
                    "scenario": current_scenario.value,
                    "sensor_id": record.sensor_id,
                    "device_id": record.device_id,
                    "event_type": record.event_type,
                    "simulation": bool(record.payload.get("simulation")) or current_scenario in {Scenario.DEAUTH_RELATED_SIMULATION},
                    "severity": assessment.severity,
                    "rules_triggered": [rule.rule_id for rule in assessment.rules_triggered],
                    "alert_created": alert is not None,
                    "alert_id": alert.alert_id if alert else None,
                }
                telemetry_events.append(telemetry_entry)
                if alert is not None or bool(record.payload.get("simulation")):
                    suspicious_entries.append({
                        "record_id": record.record_id,
                        "scenario": current_scenario.value,
                        "device_id": record.device_id,
                        "sensor_id": record.sensor_id,
                        "severity": assessment.severity,
                        "timestamp": record.timestamp,
                    })

        if suspicious_entries:
            investigation = storage.create_investigation(
                title="Synthetic demo investigation",
                description="Synthetic demonstration data only. No real network activity or attacks were generated.",
                device_id=suspicious_entries[0]["device_id"],
                sensor_id=suspicious_entries[0]["sensor_id"],
            )
            investigation_id = investigation["investigation_id"]
            for item in suspicious_entries[:3]:
                storage.add_investigation_event(
                    investigation_id,
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": item.get("timestamp") or _utc_now(),
                        "event_type": "ALERT",
                        "severity": item["severity"],
                        "message": f"Synthetic demo scenario {item['scenario']} correlated for review.",
                        "source": "system",
                        "metadata": {"scenario": item["scenario"], "record_id": item["record_id"], "simulation": True},
                    },
                )

        return {
            "mode": normalized_mode.value,
            "scenarios": [scenario.value for scenario in scenarios],
            "sensor_id": sensor_id,
            "synthetic": True,
            "no_real_network_activity": True,
            "records_generated": len(telemetry_events),
            "alerts": len(alert_ids),
            "alert_ids": alert_ids,
            "investigation_id": investigation_id,
            "telemetry": telemetry_events,
        }


def run_demo() -> dict[str, object]:
    return run_demo_sequence(mode=DemoMode.FULL)
