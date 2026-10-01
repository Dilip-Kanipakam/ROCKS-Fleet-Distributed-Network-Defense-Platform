from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from rocks.cli import main
from rocks.demo import DemoMode, run_demo_sequence
from rocks.simulator.generator import Scenario


FULL_DEMO_SCENARIOS = [
    "normal",
    "high_traffic",
    "reconnaissance_like",
    "dns_anomaly",
    "reconnect_storm",
    "deauth_related_simulation",
    "mixed_anomalous",
]
ANOMALY_DEMO_SCENARIOS = [
    "high_traffic",
    "reconnaissance_like",
    "dns_anomaly",
    "reconnect_storm",
    "deauth_related_simulation",
]


def test_full_demo_mode_contains_all_expected_scenarios():
    result = run_demo_sequence(mode=DemoMode.FULL, count=1, sensor_id="ROCKS-DEMO-TEST")

    assert result["mode"] == "full"
    assert result["synthetic"] is True
    assert result["scenarios"] == FULL_DEMO_SCENARIOS
    assert {entry["scenario"] for entry in result["telemetry"]} == set(FULL_DEMO_SCENARIOS)


def test_normal_demo_mode_contains_only_normal():
    result = run_demo_sequence(mode=DemoMode.NORMAL, count=1, sensor_id="ROCKS-DEMO-TEST")

    assert result["mode"] == "normal"
    assert result["scenarios"] == ["normal"]
    assert {entry["scenario"] for entry in result["telemetry"]} == {"normal"}


def test_anomaly_demo_mode_contains_expected_suspicious_scenarios():
    result = run_demo_sequence(mode=DemoMode.ANOMALY, count=1, sensor_id="ROCKS-DEMO-TEST")

    assert result["mode"] == "anomaly"
    assert result["scenarios"] == ANOMALY_DEMO_SCENARIOS
    assert {entry["scenario"] for entry in result["telemetry"]} == set(ANOMALY_DEMO_SCENARIOS)
    assert any(item["scenario"] == "deauth_related_simulation" for item in result["telemetry"])


def test_suspicious_demo_data_creates_investigation_id():
    result = run_demo_sequence(mode=DemoMode.ANOMALY, count=1, sensor_id="ROCKS-DEMO-TEST")

    assert result["investigation_id"] is not None
    UUID(result["investigation_id"])
    assert result["alerts"] >= 0


def test_demo_uses_isolated_temporary_storage(monkeypatch):
    captured: dict[str, str] = {}
    real_temp_dir = __import__("tempfile", fromlist=["TemporaryDirectory"]).TemporaryDirectory

    class TrackingTempDirectory:
        def __init__(self, prefix: str = ""):
            self._inner = real_temp_dir(prefix=prefix)
            captured["path"] = self._inner.name

        def __enter__(self):
            return self._inner.__enter__()

        def __exit__(self, exc_type, exc, tb):
            return self._inner.__exit__(exc_type, exc, tb)

    monkeypatch.setattr("rocks.demo.TemporaryDirectory", TrackingTempDirectory)
    result = run_demo_sequence(mode=DemoMode.NORMAL, count=1, sensor_id="ROCKS-DEMO-TEST")

    assert result["records_generated"] >= 1
    temp_path = Path(captured["path"]).resolve()
    assert "rocks-demo-" in temp_path.name
    assert not temp_path.is_relative_to(Path.cwd().resolve())


def test_demo_rejects_unknown_scenario():
    exit_code = main(["demo", "--scenario", "not-real", "--mode", "normal"])
    assert exit_code == 2


def test_demo_rejects_excessive_count():
    with pytest.raises(ValueError, match="count must be between 1 and"):
        run_demo_sequence(mode=DemoMode.NORMAL, count=1001, sensor_id="ROCKS-DEMO-TEST")


def test_demo_cli_output_is_secret_safe_and_reports_synthetic_pipeline(capsys):
    exit_code = main(["demo", "--mode", "normal", "--scenario", "normal", "--count", "2", "--sensor-id", "ROCKS-DEMO-CLI"])
    assert exit_code == 0

    output = capsys.readouterr().out.lower()
    assert "synthetic" in output
    assert "simulation only" in output or "simulation" in output
    assert "api key" not in output
    assert "smtp" not in output
    assert "password" not in output
