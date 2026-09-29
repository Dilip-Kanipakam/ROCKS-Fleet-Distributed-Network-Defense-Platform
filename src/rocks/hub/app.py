from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.staticfiles import StaticFiles

from rocks.hub.schemas import EdgeResponse, HealthResponse, StatsResponse, TelemetryIngestResponse, TelemetryResponse
from rocks.hub.service import HubService
from rocks.hub.storage import HubStorage
from rocks.edge.telemetry import TelemetryRecord
from rocks.dashboard.config import get_dashboard_config
from rocks.dashboard.routes import DashboardRoutes
from rocks.dashboard.service import DashboardService
from rocks.hub.config import get_hub_config


def create_app(database_path: str | None = None) -> FastAPI:
    hub_config = get_hub_config()
    storage = HubStorage(
        database_path or str(hub_config.database_path),
        edge_liveness_timeout_seconds=hub_config.edge_liveness_timeout_seconds,
    )
    service = HubService(storage)
    app = FastAPI(title="ROCKS Hub", version="0.1.0")
    app.state.hub_service = service
    dashboard_config = get_dashboard_config()
    if dashboard_config.enabled:
        dashboard_directory = Path(__file__).resolve().parents[1] / "dashboard"
        app.mount("/dashboard/static", StaticFiles(directory=dashboard_directory / "static"), name="dashboard-static")
        dashboard_service = DashboardService(storage, service.ml)
        app.state.dashboard_service = dashboard_service
        app.include_router(DashboardRoutes(dashboard_service, dashboard_config.auth).router())

    def auth_service(authorization: str | None) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer API key required")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer API key required")
        # The sensor ID is part of the validated telemetry body; this dependency only verifies format.

    def authenticate_query(authorization: str | None) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        token = authorization[7:].strip()
        if not token or not service.registry.authenticate_api_key(token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

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
        authorization: str | None = Header(default=None),
        sensor_id: str | None = None,
        device_id: str | None = None,
        event_type: str | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[TelemetryRecord]:
        authenticate_query(authorization)
        return service.storage.query_telemetry(sensor_id=sensor_id, device_id=device_id, event_type=event_type, limit=limit)

    @app.get("/api/v1/telemetry/context")
    def telemetry_context(
        authorization: str | None = Header(default=None),
        device_id: str | None = None,
        source_ip: str | None = None,
        sensor_id: str | None = None,
        event_type: str | None = None,
        since: str | None = None,
        until: str | None = None,
        telemetry_id: str | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        try:
            return service.storage.telemetry_context(
                device_id=device_id,
                source_ip=source_ip,
                sensor_id=sensor_id,
                event_type=event_type,
                since=since,
                until=until,
                telemetry_id=telemetry_id,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/telemetry/{telemetry_id}", response_model=TelemetryResponse)
    def get_telemetry(telemetry_id: str, authorization: str | None = Header(default=None)) -> TelemetryRecord:
        authenticate_query(authorization)
        record = service.storage.get_telemetry(telemetry_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Telemetry record not found")
        return record

    @app.get("/api/v1/edges", response_model=list[EdgeResponse])
    def list_edges(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
        authenticate_query(authorization)
        return [edge.to_dict() for edge in service.edges()]

    @app.get("/api/v1/edges/{sensor_id}", response_model=EdgeResponse)
    def get_edge(sensor_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authenticate_query(authorization)
        edge = service.registry.get(sensor_id)
        if edge is None:
            raise HTTPException(status_code=404, detail="Edge sensor not found")
        return edge.to_dict()

    @app.get("/api/v1/stats", response_model=StatsResponse)
    def stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        authenticate_query(authorization)
        return service.stats()

    return app
