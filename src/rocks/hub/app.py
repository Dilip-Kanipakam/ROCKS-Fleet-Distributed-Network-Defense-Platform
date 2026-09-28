from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, status

from rocks.hub.schemas import EdgeResponse, HealthResponse, StatsResponse, TelemetryIngestResponse, TelemetryResponse
from rocks.hub.service import HubService
from rocks.hub.storage import HubStorage
from rocks.edge.telemetry import TelemetryRecord


def create_app(database_path: str | None = None) -> FastAPI:
    storage = HubStorage(database_path or "data/rocks-hub.db")
    service = HubService(storage)
    app = FastAPI(title="ROCKS Hub", version="0.1.0")
    app.state.hub_service = service

    def auth_service(authorization: str | None) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer API key required")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer API key required")
        # The sensor ID is part of the validated telemetry body; this dependency only verifies format.

    @app.get("/api/v1/health", response_model=HealthResponse)
    def health() -> dict[str, Any]:
        return service.health()

    @app.post("/api/v1/telemetry", response_model=TelemetryIngestResponse)
    def ingest(data: dict[str, Any], authorization: str | None = Header(default=None)) -> TelemetryIngestResponse:
        auth_service(authorization)
        try:
            record = service.validate_telemetry(data)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if authorization is None or not service.registry.authenticate(record.sensor_id, authorization[7:].strip()):
            raise HTTPException(status_code=401, detail="Invalid API key")
        duplicate = not service.ingest(record)
        return TelemetryIngestResponse(status="duplicate" if duplicate else "accepted", duplicate=duplicate, telemetry_id=record.record_id)

    @app.get("/api/v1/telemetry", response_model=list[TelemetryResponse])
    def list_telemetry(
        sensor_id: str | None = None,
        device_id: str | None = None,
        event_type: str | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[TelemetryRecord]:
        return service.storage.query_telemetry(sensor_id=sensor_id, device_id=device_id, event_type=event_type, limit=limit)

    @app.get("/api/v1/telemetry/{telemetry_id}", response_model=TelemetryResponse)
    def get_telemetry(telemetry_id: str) -> TelemetryRecord:
        record = service.storage.get_telemetry(telemetry_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Telemetry record not found")
        return record

    @app.get("/api/v1/edges", response_model=list[EdgeResponse])
    def list_edges() -> list[dict[str, Any]]:
        return [edge.to_dict() for edge in service.edges()]

    @app.get("/api/v1/edges/{sensor_id}", response_model=EdgeResponse)
    def get_edge(sensor_id: str) -> dict[str, Any]:
        edge = service.registry.get(sensor_id)
        if edge is None:
            raise HTTPException(status_code=404, detail="Edge sensor not found")
        return edge.to_dict()

    @app.get("/api/v1/stats", response_model=StatsResponse)
    def stats() -> dict[str, Any]:
        return service.stats()

    return app
