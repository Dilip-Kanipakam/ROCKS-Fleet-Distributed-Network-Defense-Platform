from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum

from rocks.edge.features import TrafficFeatures
from rocks.edge.telemetry import TelemetryRecord, behavior_summary_telemetry, dns_telemetry, reconnect_telemetry


class Scenario(str, Enum):
    NORMAL = "normal"
    HIGH_TRAFFIC = "high_traffic"
    RECONNAISSANCE_LIKE = "reconnaissance_like"
    DNS_ANOMALY = "dns_anomaly"
    RECONNECT_STORM = "reconnect_storm"
    DEAUTH_RELATED_SIMULATION = "deauth_related_simulation"
    MIXED_ANOMALOUS = "mixed_anomalous"


def generate_records(
    scenario: Scenario | str,
    *,
    count: int = 1,
    sensor_id: str = "ROCKS-SIM-01",
    start: datetime | None = None,
) -> list[TelemetryRecord]:
    scenario = Scenario(scenario)
    if count < 1:
        raise ValueError("count must be greater than zero")
    start = start or datetime(2026, 1, 5, 9, tzinfo=timezone.utc)
    return [_record(scenario, index, sensor_id, start + timedelta(minutes=index)) for index in range(count)]


def _record(scenario: Scenario, index: int, sensor_id: str, timestamp: datetime) -> TelemetryRecord:
    traffic = {
        Scenario.NORMAL: 1_000,
        Scenario.HIGH_TRAFFIC: 20_000,
        Scenario.RECONNAISSANCE_LIKE: 2_000,
        Scenario.DNS_ANOMALY: 1_500,
        Scenario.RECONNECT_STORM: 1_200,
        Scenario.DEAUTH_RELATED_SIMULATION: 900,
        Scenario.MIXED_ANOMALOUS: 15_000,
    }[scenario]
    if scenario in {Scenario.DNS_ANOMALY}:
        return dns_telemetry(
            sensor_id,
            source_ip="192.0.2.10",
            source_port=53000,
            destination_ip="198.51.100.53",
            destination_port=53,
            request_count=20,
            failure_count=8,
            device_id="SIM-DEVICE-01",
            timestamp=timestamp,
        )
    if scenario == Scenario.RECONNECT_STORM:
        return reconnect_telemetry(
            sensor_id,
            reconnect_count=12,
            connection_failure_count=9,
            device_id="SIM-DEVICE-01",
            timestamp=timestamp,
        )
    payload_features = {
        "window_start": timestamp.timestamp(),
        "window_end": timestamp.timestamp() + 60,
        "packet_count": 10 + index,
        "total_bytes": traffic,
        "bytes_sent": traffic // 2,
        "bytes_received": traffic - traffic // 2,
        "connection_count": 4 if scenario != Scenario.RECONNAISSANCE_LIKE else 30,
        "active_flow_count": 2,
        "unique_destination_ip_count": 3 if scenario != Scenario.RECONNAISSANCE_LIKE else 25,
        "unique_destination_port_count": 2 if scenario != Scenario.RECONNAISSANCE_LIKE else 40,
        "unique_source_ip_count": 1,
        "tcp_packet_count": 6,
        "udp_packet_count": 3,
        "icmp_packet_count": 1,
        "dns_packet_count": 2,
        "traffic_rate": traffic / 60,
        "packet_rate": (10 + index) / 60,
        "device_id": "SIM-DEVICE-01",
    }
    features = TrafficFeatures(**payload_features)
    record = behavior_summary_telemetry(
        features,
        sensor_id,
        device_id="SIM-DEVICE-01",
        timestamp=timestamp,
    )
    if scenario == Scenario.DEAUTH_RELATED_SIMULATION:
        record.payload["simulation"] = True
        record.payload["simulation_type"] = "DEAUTH_RELATED_SIMULATION"
    return record
