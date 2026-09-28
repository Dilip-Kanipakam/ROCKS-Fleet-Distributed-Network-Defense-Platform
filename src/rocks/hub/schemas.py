from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database_status: str
    registered_edge_count: int


class TelemetryResponse(BaseModel):
    record_id: str
    schema_version: str
    timestamp: str
    sensor_id: str
    device_id: str | None
    event_type: str
    payload: dict[str, Any]
    retention_priority: int | None = None
    retention_reason: str | None = None


class TelemetryIngestResponse(BaseModel):
    status: str
    duplicate: bool
    telemetry_id: str


class EdgeResponse(BaseModel):
    sensor_id: str
    name: str
    status: str
    created_at: str
    last_seen: str | None


class StatsResponse(BaseModel):
    telemetry_records: int
    registered_edges: int
    active_edges: int
    event_type_counts: dict[str, int] = Field(default_factory=dict)
