from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

from rocks.detection.config import DetectionConfig
from rocks.edge.telemetry import TelemetryRecord
from rocks.ml.analysis import AnalysisResult


@dataclass(frozen=True)
class DetectionRuleResult:
    rule_id: str
    severity: str
    title: str
    reason: str
    evidence: dict[str, int | float | str | bool]
    simulation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionAssessment:
    telemetry_id: str
    sensor_id: str
    device_id: str | None
    timestamp: str
    severity: str
    rules_triggered: list[DetectionRuleResult]
    reasons: list[str]
    evidence: list[dict[str, Any]]
    ml_anomaly: bool | None
    ml_score: float | None
    ml_retention_priority: str | None
    risk_score: float | None
    explanation: list[str]
    simulation: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "telemetry_id": self.telemetry_id,
            "sensor_id": self.sensor_id,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "rules_triggered": [rule.to_dict() for rule in self.rules_triggered],
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
            "ml_anomaly": self.ml_anomaly,
            "ml_score": self.ml_score,
            "ml_retention_priority": self.ml_retention_priority,
            "risk_score": self.risk_score,
            "explanation": list(self.explanation),
            "simulation": self.simulation,
            "score_semantics": "Existing ML anomaly score; not an attack probability.",
        }

    @property
    def triggered(self) -> bool:
        return bool(self.rules_triggered) or self.ml_anomaly is True or self.ml_retention_priority == "HIGH"


class DetectionEngine:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    def assess(self, record: TelemetryRecord, ml_analysis: AnalysisResult | None = None) -> DetectionAssessment:
        simulation = bool(record.payload.get("simulation"))
        rules: list[DetectionRuleResult] = []
        if self.config.enabled:
            rules = self._evaluate_rules(record, simulation=simulation)

        ml_score = ml_analysis.anomaly_score if ml_analysis is not None else None
        ml_anomaly = None if ml_score is None else ml_score >= self.config.ml_anomaly_threshold
        ml_retention_priority = ml_analysis.retention_priority if ml_analysis is not None else None
        severities = [rule.severity for rule in rules]
        if ml_anomaly or ml_retention_priority == "HIGH":
            severities.append("HIGH")
        severity = "HIGH" if "HIGH" in severities else "WARNING" if severities else "INFO"
        explanations = [rule.reason for rule in rules]
        if ml_analysis is not None and ml_score is not None:
            explanations.append(
                f"ML baseline anomaly score {ml_score:.3f} compared with configured threshold {self.config.ml_anomaly_threshold:.3f}."
            )
        if ml_retention_priority == "HIGH":
            explanations.append("Existing ML retention policy assigned HIGH priority.")
        if not explanations:
            explanations.append("No configured deterministic rule or ML anomaly threshold was triggered.")
        return DetectionAssessment(
            telemetry_id=record.record_id,
            sensor_id=record.sensor_id,
            device_id=record.device_id,
            timestamp=record.timestamp,
            severity=severity,
            rules_triggered=rules,
            reasons=[rule.reason for rule in rules],
            evidence=[rule.to_dict() for rule in rules],
            ml_anomaly=ml_anomaly,
            ml_score=ml_score,
            ml_retention_priority=ml_retention_priority,
            risk_score=ml_score,
            explanation=explanations,
            simulation=simulation,
        )

    def _evaluate_rules(self, record: TelemetryRecord, *, simulation: bool) -> list[DetectionRuleResult]:
        payload = record.payload
        rules: list[DetectionRuleResult] = []
        window = _number(payload, "window_seconds", self.config.window_seconds)
        if window <= 0:
            window = self.config.window_seconds

        if record.event_type == "BEHAVIOR_SUMMARY":
            traffic_rate = _number(payload, "traffic_rate")
            if traffic_rate > self.config.high_traffic_rate:
                rules.append(
                    DetectionRuleResult(
                        "HIGH_TRAFFIC", "WARNING", "High traffic activity",
                        "Observed traffic rate was unusually high and exceeded the configured threshold.",
                        {"traffic_rate": traffic_rate, "threshold": self.config.high_traffic_rate, "window_seconds": window},
                    )
                )
            connections = _number(payload, "connection_count")
            connection_rate = connections / window
            if connection_rate > self.config.connection_burst_rate:
                rules.append(
                    DetectionRuleResult(
                        "CONNECTION_BURST", "WARNING", "High connection activity",
                        "Connection activity exceeded the configured rate for this observation window.",
                        {"connection_count": connections, "observed_rate": connection_rate, "threshold": self.config.connection_burst_rate, "window_seconds": window},
                    )
                )
            unique_destinations = _number(payload, "unique_destination_ip_count")
            unique_ports = _number(payload, "unique_destination_port_count")
            repeated = _number(payload, "repeated_destination_count")
            if unique_destinations >= self.config.unique_destination_count or unique_ports >= self.config.unique_destination_port_count:
                rules.append(
                    DetectionRuleResult(
                        "RECONNAISSANCE_LIKE", "HIGH", "Reconnaissance-like behavior detected",
                        "The device contacted an unusually high number of destinations or ports; this is not proof of scanning.",
                        {"unique_destination_count": unique_destinations, "destination_count_threshold": self.config.unique_destination_count, "unique_destination_port_count": unique_ports, "destination_port_threshold": self.config.unique_destination_port_count, "repeated_destination_count": repeated, "window_seconds": window},
                    )
                )
            dns_requests = _number(payload, "dns_request_count")
            dns_failures = _number(payload, "dns_failure_count")
            self._append_dns_rule(rules, dns_requests, dns_failures, window)
            reconnects = _number(payload, "reconnect_count")
            failures = _number(payload, "connection_failure_count")
            self._append_reconnect_rule(rules, reconnects, failures, window)

        elif record.event_type == "DNS":
            requests = _number(payload, "request_count")
            failures = _number(payload, "failure_count")
            self._append_dns_rule(rules, requests, failures, window)

        elif record.event_type == "RECONNECT":
            reconnects = _number(payload, "reconnect_count")
            failures = _number(payload, "connection_failure_count")
            self._append_reconnect_rule(rules, reconnects, failures, window)

        deauth_count = _number(payload, "deauth_count")
        simulated_deauth = simulation and str(payload.get("simulation_type", "")).upper() == "DEAUTH_RELATED_SIMULATION"
        explicit_real_evidence = (
            not simulation
            and str(payload.get("management_frame_type", payload.get("frame_type", ""))).lower() in {"deauth", "deauthentication"}
            and payload.get("evidence_source") == "802.11_management_frame"
            and deauth_count >= self.config.deauth_count
        )
        if simulated_deauth:
            rules.append(
                DetectionRuleResult(
                    "DEAUTH_RELATED", "WARNING", "Simulated deauthentication-related telemetry",
                    "Simulation-only deauthentication-related data, not observed Wi-Fi activity.",
                    {"simulation_type": "DEAUTH_RELATED_SIMULATION", "simulated_event": True},
                    simulation=True,
                )
            )
        elif explicit_real_evidence:
            rules.append(
                DetectionRuleResult(
                    "DEAUTH_RELATED", "HIGH", "Deauthentication-related telemetry detected",
                    "Explicit 802.11 management-frame evidence met the configured count threshold; this does not by itself establish malicious intent.",
                    {"deauth_count": deauth_count, "threshold": self.config.deauth_count, "evidence_source": "802.11_management_frame"},
                )
            )
        return rules

    def _append_dns_rule(self, rules: list[DetectionRuleResult], requests: float, failures: float, window: float) -> None:
        rate = requests / window
        failure_rate = failures / requests if requests > 0 else 0.0
        if rate > self.config.dns_request_rate or failure_rate >= self.config.dns_failure_rate:
            rules.append(
                DetectionRuleResult(
                    "DNS_ANOMALY", "WARNING", "DNS anomaly",
                    "DNS request rate or failure ratio exceeded the configured threshold; telemetry does not establish tunneling.",
                    {"request_count": requests, "failure_count": failures, "request_rate": rate, "request_rate_threshold": self.config.dns_request_rate, "failure_rate": failure_rate, "failure_rate_threshold": self.config.dns_failure_rate, "window_seconds": window},
                )
            )

    def _append_reconnect_rule(self, rules: list[DetectionRuleResult], reconnects: float, failures: float, window: float) -> None:
        if reconnects >= self.config.reconnect_count:
            rules.append(
                DetectionRuleResult(
                    "RECONNECT_STORM", "HIGH", "Reconnect storm",
                    "Observed reconnect count met or exceeded the configured threshold.",
                    {"reconnect_count": reconnects, "connection_failure_count": failures, "threshold": self.config.reconnect_count, "window_seconds": window},
                )
            )


def _number(payload: dict[str, Any], field: str, default: float = 0.0) -> float:
    value = payload.get(field, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return default
    return max(0.0, float(value))
