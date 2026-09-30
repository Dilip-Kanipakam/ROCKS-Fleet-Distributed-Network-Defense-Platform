from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.staticfiles import StaticFiles

from rocks.hub.schemas import EdgeResponse, HealthResponse, StatsResponse, TelemetryIngestResponse, TelemetryResponse
from rocks.hub.service import HubService
from rocks.hub.storage import HubStorage
from rocks.hub.investigation import (
    INVESTIGATION_STATUSES,
    resolve_time_range,
    validate_case_event,
    validate_case_text,
    validate_identifier,
    validate_investigation_id,
)
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

    @app.get("/api/v1/investigations")
    def investigate_device(
        authorization: str | None = Header(default=None),
        device_id: str = Query(..., min_length=1, max_length=128),
        start: str | None = None,
        end: str | None = None,
        sensor_id: str | None = Query(default=None, min_length=1, max_length=128),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        try:
            device_id = validate_identifier(device_id, field="device_id")
            if sensor_id is not None:
                sensor_id = validate_identifier(sensor_id, field="sensor_id")
            start_at, end_at = resolve_time_range(start, end)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        events = service.storage.investigation_timeline(
            device_id=device_id,
            start=start_at,
            end=end_at,
            sensor_id=sensor_id,
        )
        return {
            "device": {"device_id": device_id, "sensor_id": sensor_id},
            "time_range": {"start": start_at, "end": end_at},
            "events": events,
        }

    @app.post("/api/v1/investigations", status_code=status.HTTP_201_CREATED)
    def create_investigation(
        data: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        allowed = {"title", "description", "device_id", "sensor_id"}
        if set(data) - allowed:
            raise HTTPException(status_code=422, detail="Investigation contains unsupported fields")
        try:
            title = validate_case_text(data.get("title"), field="title", required=True, maximum=200)
            description = validate_case_text(data.get("description", ""), field="description", required=False, maximum=4000)
            device_id = data.get("device_id")
            sensor_id = data.get("sensor_id")
            if device_id is not None:
                device_id = validate_identifier(device_id, field="device_id")
            if sensor_id is not None:
                sensor_id = validate_identifier(sensor_id, field="sensor_id")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return service.storage.create_investigation(
            title=title,
            description=description,
            device_id=device_id,
            sensor_id=sensor_id,
        )

    @app.get("/api/v1/investigations/{investigation_id}")
    def get_investigation(
        investigation_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        investigation = service.storage.get_investigation(investigation_id)
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return investigation

    @app.post("/api/v1/investigations/{investigation_id}/events", status_code=status.HTTP_201_CREATED)
    def add_investigation_event(
        investigation_id: str,
        data: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            event = validate_case_event(data)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            stored = service.storage.add_investigation_event(investigation_id, event)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if stored is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return stored

    @app.get("/api/v1/investigations/{investigation_id}/timeline")
    def investigation_timeline(
        investigation_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        events = service.storage.investigation_events(investigation_id)
        if events is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return {"investigation_id": investigation_id, "events": events}

    @app.patch("/api/v1/investigations/{investigation_id}")
    def update_investigation(
        investigation_id: str,
        data: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        allowed = {"title", "description", "status"}
        if not data or set(data) - allowed:
            raise HTTPException(status_code=422, detail="Provide supported investigation fields to update")
        changes: dict[str, Any] = {}
        try:
            if "title" in data:
                changes["title"] = validate_case_text(data["title"], field="title", required=True, maximum=200)
            if "description" in data:
                changes["description"] = validate_case_text(data["description"], field="description", required=False, maximum=4000)
            if "status" in data:
                if not isinstance(data["status"], str) or data["status"] not in INVESTIGATION_STATUSES:
                    raise ValueError("Invalid investigation status")
                changes["status"] = data["status"]
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            investigation = service.storage.update_investigation(investigation_id, changes)
        except ValueError as exc:
            code = 409 if "transition" in str(exc) or "Closed investigations" in str(exc) else 422
            raise HTTPException(status_code=code, detail=str(exc)) from exc
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return investigation

    @app.post("/api/v1/investigations/{investigation_id}/close")
    def close_investigation(
        investigation_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_query(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            investigation = service.storage.close_investigation(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return investigation

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
