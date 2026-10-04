from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request
from dataclasses import dataclass

from rocks.edge.buffer import TelemetryBuffer
from rocks.edge.telemetry import TelemetryRecord, telemetry_to_json
from rocks.logging_config import configure_logging


@dataclass(frozen=True)
class SendResult:
    sent: int
    failed: int


class EdgeSender:
    """Bounded, acknowledgement-driven sender for buffered local telemetry."""

    def __init__(
        self,
        hub_url: str,
        api_key: str,
        *,
        timeout_seconds: float = 10.0,
        max_attempts: int = 1,
        max_concurrent_requests: int = 16,
    ) -> None:
        if not hub_url or not api_key:
            raise ValueError("hub_url and api_key are required")
        self.endpoint = hub_url.rstrip("/") + "/api/v1/telemetry"
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max(1, max_attempts)
        if max_concurrent_requests <= 0:
            raise ValueError("max_concurrent_requests must be greater than zero")
        self.max_concurrent_requests = max_concurrent_requests
        self._logger = configure_logging()

    def send_record(self, record: TelemetryRecord) -> bool:
        request = urllib.request.Request(
            self.endpoint,
            data=telemetry_to_json(record).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        for _attempt in range(self.max_attempts):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    if 200 <= response.status < 300:
                        body = json.loads(response.read().decode("utf-8"))
                        self._logger.info(
                            "EDGE_HUB_TELEMETRY_ACCEPTED telemetry_id=%s status=%s http_status=%s",
                            body.get("telemetry_id", record.record_id),
                            body.get("status", "unknown"),
                            response.status,
                        )
                        return True
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
                self._logger.warning("Hub telemetry delivery failed: %s", exc.__class__.__name__)
        return False

    def send_pending(
        self,
        buffer: TelemetryBuffer,
        *,
        limit: int = 100,
        sensor_id: str | None = None,
    ) -> SendResult:
        sent = 0
        failed = 0
        records = buffer.peek(limit, sensor_id=sensor_id)
        if not records:
            return SendResult(sent=0, failed=0)
        with ThreadPoolExecutor(max_workers=min(self.max_concurrent_requests, len(records))) as executor:
            futures = [executor.submit(self.send_record, record) for record in records]
            for record, future in zip(records, futures):
                try:
                    acknowledged = future.result()
                except Exception:
                    acknowledged = False
                if acknowledged:
                    buffer.remove(record.record_id)
                    sent += 1
                else:
                    failed += 1
        return SendResult(sent=sent, failed=failed)
