from __future__ import annotations

import signal
import ipaddress
import json
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.capture import PacketCapture
from rocks.edge.features import aggregate_features_by_source
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import PacketMetadata, parse_packet
from rocks.edge.sender import EdgeSender, SendResult
from rocks.edge.storage import TelemetryStorage
from rocks.edge.telemetry import (
    TelemetryRecord,
    behavior_summary_telemetry,
    connection_telemetry,
    dns_telemetry,
)
from rocks.logging_config import configure_logging


@dataclass(frozen=True)
class EdgeAgentConfig:
    sensor_id: str = "ROCKS-EDGE-01"
    interface: str = ""
    hub_url: str = ""
    api_key: str = ""
    send_interval_seconds: float = 5.0
    buffer_limit: int = 10_000
    max_active_flows: int = 10_000
    telemetry_window_seconds: float = 60.0
    database_path: Path | None = None
    buffer_path: Path | None = None


class EdgeAgent:
    """Connect capture, metadata features, local-first storage, and Hub sending."""

    def __init__(self, config: EdgeAgentConfig) -> None:
        self.config = config
        self.logger = configure_logging()
        self.stop_event = threading.Event()
        self.capture: PacketCapture | None = None
        self.storage = TelemetryStorage(config.database_path)
        self.storage.initialize()
        self.buffer = TelemetryBuffer(config.buffer_path, buffer_limit=config.buffer_limit)
        self.flow_tracker = FlowTracker(max_active_flows=config.max_active_flows)
        self._packets: OrderedDict[tuple[object, ...], PacketMetadata] = OrderedDict()
        self._flow_source_macs: dict[tuple[str, str, int, int, str], str] = {}
        self._lock = threading.Lock()
        self._feature_flush_lock = threading.Lock()
        self._packet_drop_report_lock = threading.Lock()
        self._last_feature_flush = time.monotonic()
        self._feature_window_started = time.time()
        self._last_flow_expire_timestamp: float | None = None
        self._packet_metadata_drops_unreported = 0
        self._window_emit_cache: OrderedDict[tuple[str, ...], float] = OrderedDict()
        self._window_emit_cache_limit = max(1024, config.max_active_flows)
        self.last_successful_send: str | None = None
        self.last_hub_error: str | None = None
        self.telemetry_generated = 0
        self.sender = EdgeSender(config.hub_url, config.api_key) if config.hub_url and config.api_key else None

    def process_packet(self, packet: Any) -> None:
        try:
            metadata = parse_packet(packet)
            if metadata.source_ip is None or metadata.destination_ip is None:
                return
            expired = []
            with self._lock:
                if (
                    self._last_flow_expire_timestamp is None
                    or metadata.timestamp - self._last_flow_expire_timestamp >= 1.0
                ):
                    expired = self.flow_tracker.expire(metadata.timestamp)
                    self._last_flow_expire_timestamp = metadata.timestamp
                expired_records = [self._connection_record(flow) for flow in expired]
                for flow in expired:
                    self._flow_source_macs.pop(_flow_key(flow), None)
                packet_key = _packet_window_key(metadata)
                existing = self._packets.get(packet_key)
                if existing is not None:
                    self._packets[packet_key] = replace(
                        existing,
                        timestamp=max(existing.timestamp, metadata.timestamp),
                        packet_count=existing.packet_count + metadata.packet_count,
                        aggregate_bytes=(existing.aggregate_bytes or 0) + (metadata.aggregate_bytes or 0),
                    )
                elif len(self._packets) < self.config.buffer_limit:
                    self._packets[packet_key] = metadata
                else:
                    self._packet_metadata_drops_unreported += metadata.packet_count
                if not metadata.dns_related:
                    flow = self.flow_tracker.update(metadata, expire_stale=False)
                    evicted_flow = self.flow_tracker.last_evicted
                    if evicted_flow is not None:
                        self._flow_source_macs.pop(_flow_key(evicted_flow), None)
                        expired_records.append(self._connection_record(evicted_flow))
                    if flow is not None and metadata.source_mac:
                        self._flow_source_macs.setdefault(_flow_key(flow), metadata.source_mac)
            for record in expired_records:
                self._store_local(record)
        except Exception:
            self.logger.exception("Edge packet metadata processing failed")

    def flush_features(self) -> list[TelemetryRecord]:
        with self._feature_flush_lock:
            return self._flush_features_locked()

    def _flush_features_if_due(self) -> list[TelemetryRecord]:
        if time.monotonic() - self._last_feature_flush < self.config.telemetry_window_seconds:
            return []
        return self.flush_features()

    def _flush_features_locked(self) -> list[TelemetryRecord]:
        self._report_packet_metadata_drops()
        window_start = self._feature_window_started
        window_end = time.time()
        with self._lock:
            packets = list(self._packets.values())
            self._packets.clear()
            expired_flows = self.flow_tracker.expire(window_end)
            expired_records = [self._connection_record(flow) for flow in expired_flows]
            for flow in expired_flows:
                self._flow_source_macs.pop(_flow_key(flow), None)
            flows = self.flow_tracker.snapshot()
        self._last_feature_flush = time.monotonic()
        self._feature_window_started = window_end
        records: list[TelemetryRecord] = expired_records + self._dns_records(packets, window_start=window_start, window_end=window_end)
        for record in records:
            self._store_local(record)
        if not packets:
            return records
        for features in aggregate_features_by_source(
            packets,
            flows,
            window_start=window_start,
            window_end=window_end,
            window_seconds=self.config.telemetry_window_seconds,
        ):
            source_ip = (features.device_id or "").split("|", 1)[0]
            try:
                if not ipaddress.ip_address(source_ip).is_private:
                    continue
            except ValueError:
                continue
            record = behavior_summary_telemetry(
                features,
                self.config.sensor_id,
                device_id=features.device_id,
                window_seconds=self.config.telemetry_window_seconds,
            )
            logical_key = ("BEHAVIOR_SUMMARY", features.device_id or self.config.sensor_id, str(window_start), str(window_end))
            self._store_local(record, logical_key=logical_key)
            records.append(record)
        return records

    def _dns_records(self, packets: list[PacketMetadata], *, window_start: float | None = None, window_end: float | None = None) -> list[TelemetryRecord]:
        dns_groups: dict[tuple[str, str, int | None, str], list[PacketMetadata]] = {}
        for packet in packets:
            # A destination port of 53 identifies an observed query direction.
            # Response/failure semantics are unavailable from current metadata.
            if not packet.dns_related or packet.destination_port != 53:
                continue
            key = (
                packet.source_ip or "",
                packet.destination_ip or "",
                packet.destination_port,
                packet.protocol,
            )
            dns_groups.setdefault(key, []).append(packet)

        records = []
        for (source_ip, destination_ip, destination_port, protocol), group in dns_groups.items():
            source_macs = {packet.source_mac for packet in group if packet.source_mac}
            source_mac = next(iter(source_macs)) if len(source_macs) == 1 else None
            device_id = f"{source_ip}|{source_mac}" if source_mac else None
            observed_at = datetime.fromtimestamp(max(packet.timestamp for packet in group), tz=timezone.utc)
            record = dns_telemetry(
                self.config.sensor_id,
                source_ip=source_ip,
                source_port=None,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol,
                request_count=sum(packet.packet_count for packet in group),
                failure_count=0,
                device_id=device_id,
                timestamp=observed_at,
            )
            logical_key = (
                "DNS",
                device_id or self.config.sensor_id,
                source_ip,
                destination_ip,
                str(destination_port),
                protocol,
                str(window_start if window_start is not None else observed_at.timestamp()),
                str(window_end if window_end is not None else observed_at.timestamp()),
            )
            self._store_local(record, logical_key=logical_key)
            records.append(record)
        return records

    def _connection_record(self, flow: Any) -> TelemetryRecord:
        source_mac = self._flow_source_macs.get(_flow_key(flow))
        device_id = f"{flow.source_ip}|{source_mac}" if source_mac else None
        observed_at = datetime.fromtimestamp(flow.last_seen, tz=timezone.utc)
        return connection_telemetry(
            flow,
            self.config.sensor_id,
            device_id=device_id,
            source_mac=source_mac,
            bytes_sent=flow.bytes,
            bytes_received=flow.reverse_bytes if flow.reverse_packet_count else None,
            timestamp=observed_at,
        )

    def _fallback_logical_key(self, record: TelemetryRecord) -> tuple[str, ...] | None:
        try:
            timestamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
        slot_seconds = max(1.0, self.config.telemetry_window_seconds)
        if record.event_type == "BEHAVIOR_SUMMARY":
            device_id = record.device_id or self.config.sensor_id
            return (record.event_type, device_id, str(int(timestamp // slot_seconds)))
        if record.event_type == "DNS":
            payload = record.payload
            device_id = record.device_id or self.config.sensor_id
            source_ip = str(payload.get("source_ip") or "")
            destination_ip = str(payload.get("destination_ip") or "")
            destination_port = str(payload.get("destination_port") or "")
            protocol = str(payload.get("protocol") or "")
            return (record.event_type, device_id, source_ip, destination_ip, destination_port, protocol, str(int(timestamp // slot_seconds)))
        return None

    def _record_seen_recently(self, logical_key: tuple[str, ...] | None, *, record: TelemetryRecord | None = None) -> bool:
        key = logical_key or (self._fallback_logical_key(record) if record is not None else None)
        if key is None:
            return False
        if key in self._window_emit_cache:
            self.logger.debug("Telemetry deduplicated by logical window key: %s", key)
            return True
        self._window_emit_cache[key] = time.monotonic()
        self._window_emit_cache.move_to_end(key)
        while len(self._window_emit_cache) > self._window_emit_cache_limit:
            self._window_emit_cache.popitem(last=False)
        return False

    def _store_local(self, record: TelemetryRecord, *, logical_key: tuple[str, ...] | None = None) -> None:
        if self._record_seen_recently(logical_key, record=record):
            return
        if not self.storage.insert_telemetry(record):
            return
        if not self.buffer.add(record):
            self.logger.warning("Telemetry already exists in buffer: %s", record.record_id)
            return
        self.telemetry_generated += 1
        self.logger.info("EDGE_TELEMETRY_GENERATED sensor_id=%s event_type=%s", self.config.sensor_id, record.event_type)

    def send_pending(self) -> SendResult:
        if self.sender is None:
            return SendResult(sent=0, failed=0)
        result = self.sender.send_pending(
            self.buffer,
            limit=min(100, self.config.buffer_limit),
            sensor_id=self.config.sensor_id,
        )
        if result.sent:
            self.last_successful_send = _utc_now()
            self.logger.info("EDGE_HUB_SEND_SUCCESS count=%s", result.sent)
        if result.failed:
            self.last_hub_error = "Hub delivery failed; records remain buffered"
            self.logger.warning("EDGE_HUB_SEND_FAILURE count=%s", result.failed)
        return result

    def run(self) -> None:
        if not self.config.interface:
            raise ValueError("An interface is required unless --dry-run is used")
        self.capture = PacketCapture(self.config.interface, self.process_packet)
        sender_thread = threading.Thread(target=self._send_loop, name="rocks-edge-sender", daemon=True)
        sender_thread.start()
        self.logger.info("EDGE_STARTED sensor_id=%s", self.config.sensor_id)
        try:
            self.capture.start()
        finally:
            self.stop()
            self.flush_features()
            sender_thread.join(timeout=self.config.send_interval_seconds + 1)
            self.logger.info("EDGE_STOPPED sensor_id=%s", self.config.sensor_id)

    def run_dry_run(self, records: list[TelemetryRecord]) -> SendResult:
        for record in records:
            self._store_local(record)
        return self.send_pending()

    def stop(self) -> None:
        self.stop_event.set()
        if self.capture is not None:
            self.capture.stop()

    def hub_health(self) -> bool:
        if not self.config.hub_url:
            return False
        try:
            with urllib.request.urlopen(self.config.hub_url.rstrip("/") + "/api/v1/health", timeout=5) as response:
                return response.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def _send_loop(self) -> None:
        drain_backlog = False
        batch_limit = min(100, self.config.buffer_limit)
        while True:
            if not drain_backlog and self.stop_event.wait(self.config.send_interval_seconds):
                break
            try:
                self._report_packet_metadata_drops()
                self._expire_idle_flows()
                self._flush_features_if_due()
                result = self.send_pending()
                drain_backlog = (
                    result.sent >= batch_limit
                    and result.failed == 0
                    and not self.stop_event.is_set()
                )
            except (OSError, sqlite3.Error) as exc:
                drain_backlog = False
                self.logger.warning(
                    "Edge persistence or delivery cycle failed; retrying: %s",
                    type(exc).__name__,
                )

    def _report_packet_metadata_drops(self) -> None:
        with self._packet_drop_report_lock:
            with self._lock:
                dropped = self._packet_metadata_drops_unreported
            if dropped:
                self.buffer.record_dropped_packets(dropped)
                with self._lock:
                    self._packet_metadata_drops_unreported -= dropped
                self.logger.error(
                    "EDGE_FEATURE_WINDOW_OVERFLOW dropped_packets=%s total_dropped_packets=%s",
                    dropped,
                    self.buffer.dropped_packets,
                )

    def _expire_idle_flows(self) -> None:
        now = time.time()
        with self._lock:
            expired = self.flow_tracker.expire(now)
            records = [self._connection_record(flow) for flow in expired]
            for flow in expired:
                self._flow_source_macs.pop(_flow_key(flow), None)
        for record in records:
            self._store_local(record)

    def status(self) -> dict[str, object]:
        return {
            "sensor_id": self.config.sensor_id,
            "interface": self.config.interface or "not configured",
            "hub_url": self.config.hub_url or "not configured",
            "status": "STOPPED" if self.capture is None else "RUNNING",
            "capture_status": "RUNNING" if self.capture is not None and not self.stop_event.is_set() else "STOPPED",
            "buffer_records": self.buffer.size(),
            "buffer_dropped_records": self.buffer.dropped_records,
            "packet_metadata_dropped": self.buffer.dropped_packets + self._packet_metadata_drops_unreported,
            "telemetry_records": self.storage.count(),
            "last_successful_send": self.last_successful_send,
            "last_hub_error": self.last_hub_error,
        }


def install_signal_handlers(agent: EdgeAgent) -> None:
    def stop_handler(_signum: int, _frame: Any) -> None:
        agent.stop()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _flow_key(flow: Any) -> tuple[str, str, int, int, str]:
    first, second = sorted(
        ((flow.source_ip, flow.source_port), (flow.destination_ip, flow.destination_port))
    )
    return first[0], second[0], first[1], second[1], flow.protocol


def _packet_window_key(packet: PacketMetadata) -> tuple[object, ...]:
    return (
        packet.source_ip,
        packet.destination_ip,
        packet.protocol,
        packet.destination_port,
        packet.source_mac,
        packet.dns_related,
    )
