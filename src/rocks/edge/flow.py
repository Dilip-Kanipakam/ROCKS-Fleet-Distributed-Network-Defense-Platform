from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from rocks.edge.parser import PacketMetadata
from rocks.logging_config import configure_logging


@dataclass(frozen=True)
class FlowKey:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str


@dataclass
class FlowRecord:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    bytes: int = 0
    reverse_packet_count: int = 0
    reverse_bytes: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def packets_per_second(self) -> float:
        return self.packet_count / self.duration if self.duration > 0 else 0.0

    @property
    def bytes_per_second(self) -> float:
        return self.bytes / self.duration if self.duration > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.update(
            duration=self.duration,
            packets_per_second=self.packets_per_second,
            bytes_per_second=self.bytes_per_second,
        )
        return result


class FlowTracker:
    """Track active five-tuple flows with time-based expiration."""

    def __init__(self, expiration_seconds: float = 300.0, max_active_flows: int = 10_000) -> None:
        if expiration_seconds <= 0:
            raise ValueError("expiration_seconds must be greater than zero")
        if isinstance(max_active_flows, bool) or not isinstance(max_active_flows, int) or max_active_flows <= 0:
            raise ValueError("max_active_flows must be a positive integer")
        self.expiration_seconds = expiration_seconds
        self.max_active_flows = max_active_flows
        self._flows: dict[FlowKey, FlowRecord] = {}
        self.last_evicted: FlowRecord | None = None
        self._logger = configure_logging()

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    @property
    def flows(self) -> tuple[FlowRecord, ...]:
        return tuple(self._flows.values())

    def update(self, metadata: PacketMetadata, *, expire_stale: bool = True) -> FlowRecord | None:
        self.last_evicted = None
        if metadata.source_ip is None or metadata.destination_ip is None:
            return None

        source_endpoint = (metadata.source_ip, metadata.source_port or 0)
        destination_endpoint = (metadata.destination_ip, metadata.destination_port or 0)
        first_endpoint, second_endpoint = sorted((source_endpoint, destination_endpoint))
        key = FlowKey(
            source_ip=first_endpoint[0],
            destination_ip=second_endpoint[0],
            source_port=first_endpoint[1],
            destination_port=second_endpoint[1],
            protocol=metadata.protocol,
        )
        record = self._flows.get(key)
        if record is None:
            if expire_stale:
                self.expire(metadata.timestamp)
            if len(self._flows) >= self.max_active_flows:
                oldest_key = min(self._flows, key=lambda item: (self._flows[item].last_seen, repr(item)))
                self.last_evicted = self._flows.pop(oldest_key)
                self._logger.warning("Edge flow capacity reached; evicted oldest flow %s", oldest_key)
            record = FlowRecord(
                source_ip=metadata.source_ip,
                destination_ip=metadata.destination_ip,
                source_port=metadata.source_port or 0,
                destination_port=metadata.destination_port or 0,
                protocol=key.protocol,
                first_seen=metadata.timestamp,
                last_seen=metadata.timestamp,
            )
            self._flows[key] = record
            self._logger.debug("Edge flow created: %s", key)

        record.last_seen = max(record.last_seen, metadata.timestamp)
        record.packet_count += 1
        if (
            metadata.source_ip == record.source_ip
            and (metadata.source_port or 0) == record.source_port
            and metadata.destination_ip == record.destination_ip
            and (metadata.destination_port or 0) == record.destination_port
        ):
            record.bytes += metadata.packet_length
        else:
            record.reverse_packet_count += 1
            record.reverse_bytes += metadata.packet_length
        if expire_stale:
            self.expire(metadata.timestamp)
        return record

    def expire(self, now: float) -> list[FlowRecord]:
        expired_keys = [
            key
            for key, record in self._flows.items()
            if now - record.last_seen >= self.expiration_seconds
        ]
        expired = [self._flows.pop(key) for key in expired_keys]
        for record in expired:
            self._logger.debug(
                "Edge flow expired: %s:%s -> %s:%s (%s)",
                record.source_ip,
                record.source_port,
                record.destination_ip,
                record.destination_port,
                record.protocol,
            )
        return expired

    def snapshot(self) -> tuple[FlowRecord, ...]:
        return self.flows
