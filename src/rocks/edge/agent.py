from __future__ import annotations

import signal
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.capture import PacketCapture
from rocks.edge.features import FeatureAggregator, aggregate_features
from rocks.edge.flow import FlowTracker
from rocks.edge.parser import PacketMetadata, parse_packet
from rocks.edge.sender import EdgeSender, SendResult
from rocks.edge.storage import TelemetryStorage
from rocks.edge.telemetry import TelemetryRecord, behavior_summary_telemetry
from rocks.logging_config import configure_logging


@dataclass(frozen=True)
class EdgeAgentConfig:
    sensor_id: str = "ROCKS-EDGE-01"
    interface: str = ""
    hub_url: str = ""
    api_key: str = ""
    send_interval_seconds: float = 5.0
    buffer_limit: int = 10_000
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
        self.buffer = TelemetryBuffer(config.buffer_path)
        self.feature_aggregator = FeatureAggregator(config.telemetry_window_seconds, config.buffer_limit)
        self.flow_tracker = FlowTracker()
        self._packets: list[PacketMetadata] = []
        self._lock = threading.Lock()
        self.last_successful_send: str | None = None
        self.last_hub_error: str | None = None
        self.telemetry_generated = 0
        self.sender = EdgeSender(config.hub_url, config.api_key) if config.hub_url and config.api_key else None

    def process_packet(self, packet: Any) -> None:
        try:
            metadata = parse_packet(packet)
            if metadata.source_ip is None or metadata.destination_ip is None:
                return
            with self._lock:
                self._packets.append(metadata)
                if len(self._packets) > self.config.buffer_limit:
                    self._packets.pop(0)
                self.feature_aggregator.add(metadata)
                self.flow_tracker.update(metadata)
        except Exception:
            self.logger.exception("Edge packet metadata processing failed")

    def flush_features(self) -> TelemetryRecord | None:
        with self._lock:
            if not self._packets:
                return None
            packets = list(self._packets)
            self._packets.clear()
            flows = self.flow_tracker.snapshot()
        features = aggregate_features(packets, flows, window_seconds=self.config.telemetry_window_seconds)
        record = behavior_summary_telemetry(
            features,
            self.config.sensor_id,
            device_id=features.device_id,
            window_seconds=self.config.telemetry_window_seconds,
        )
        self.storage.insert_telemetry(record)
        self.buffer.add(record)
        self.telemetry_generated += 1
        self.logger.info("EDGE_TELEMETRY_GENERATED sensor_id=%s", self.config.sensor_id)
        return record

    def send_pending(self) -> SendResult:
        if self.sender is None:
            return SendResult(sent=0, failed=0)
        result = self.sender.send_pending(self.buffer, limit=min(100, self.config.buffer_limit))
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

    def run_dry_run(self, records: list[TelemetryRecord]) -> None:
        for record in records:
            self.storage.insert_telemetry(record)
            self.buffer.add(record)
            self.telemetry_generated += 1
        self.send_pending()

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
        while not self.stop_event.wait(self.config.send_interval_seconds):
            self.flush_features()
            self.send_pending()

    def status(self) -> dict[str, object]:
        return {
            "sensor_id": self.config.sensor_id,
            "interface": self.config.interface or "not configured",
            "hub_url": self.config.hub_url or "not configured",
            "status": "STOPPED" if self.capture is None else "RUNNING",
            "capture_status": "RUNNING" if self.capture is not None and not self.stop_event.is_set() else "STOPPED",
            "buffer_records": self.buffer.size(),
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
