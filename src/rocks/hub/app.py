from __future__ import annotations

import sqlite3
import re
import ipaddress
import hmac
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Path as APIPath, Query, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from rocks.hub.schemas import EdgeResponse, HealthResponse, StatsResponse, TelemetryIngestResponse, TelemetryResponse
from rocks.hub.service import HubService
from rocks.hub.storage import HubStorage
from rocks.hub.investigation import (
    INVESTIGATION_STATUSES,
    resolve_time_range,
    validate_analyst_action,
    validate_analyst_note,
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


_MAX_REQUEST_BODY_BYTES = 128 * 1024


class RequestBodyLimitMiddleware:
    def __init__(self, app: Any, maximum_bytes: int = _MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.maximum_bytes = maximum_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length)
            except ValueError:
                response = JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
                await response(scope, receive, send)
                return
            if content_length < 0 or content_length > self.maximum_bytes:
                response = JSONResponse({"detail": "Request body exceeds the 128 KiB limit"}, status_code=413)
                await response(scope, receive, send)
                return

        messages: list[dict[str, Any]] = []
        body_size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body_size += len(message.get("body", b""))
            if body_size > self.maximum_bytes:
                response = JSONResponse({"detail": "Request body exceeds the 128 KiB limit"}, status_code=413)
                await response(scope, receive, send)
                return
            messages.append(message)
            if not message.get("more_body", False):
                break

        async def replay_receive() -> dict[str, Any]:
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


def create_app(database_path: str | None = None) -> FastAPI:
    hub_config = get_hub_config()
    storage = HubStorage(
        database_path or str(hub_config.database_path),
        edge_liveness_timeout_seconds=hub_config.edge_liveness_timeout_seconds,
    )
    service = HubService(storage)
    app = FastAPI(title="ROCKS Hub", version="0.1.0")
    app.add_middleware(RequestBodyLimitMiddleware)
    app.state.hub_service = service

    @app.exception_handler(sqlite3.Error)
    async def sqlite_error_handler(_request: Any, exc: sqlite3.Error) -> JSONResponse:
        service._logger.error("SQLite request failed error_type=%s", type(exc).__name__)
        return JSONResponse({"detail": "Storage is temporarily unavailable"}, status_code=503)

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

    def authenticate_query(authorization: str | None) -> str | None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        if hub_config.admin_api_key and hmac.compare_digest(token, hub_config.admin_api_key):
            return None
        sensor_id = service.registry.identify_api_key(token)
        if sensor_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return sensor_id

    def sensor_scope(scope: str | None, requested_sensor_id: str | None) -> str | None:
        if scope is None:
            return requested_sensor_id
        if requested_sensor_id is not None and requested_sensor_id != scope:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sensor access is limited to its own records")
        return scope

    def authenticate_admin(authorization: str | None) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        token = authorization[7:].strip()
        if not hub_config.admin_api_key or not token or not hmac.compare_digest(token, hub_config.admin_api_key):
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
        sensor_id: str | None = Query(default=None, min_length=1, max_length=64),
        device_id: str | None = Query(default=None, min_length=1, max_length=128),
        event_type: str | None = Query(default=None, min_length=1, max_length=32),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[TelemetryRecord]:
        scope = authenticate_query(authorization)
        sensor_id = sensor_scope(scope, sensor_id)
        if sensor_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", sensor_id):
            raise HTTPException(status_code=422, detail="Invalid sensor_id")
        if device_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,127}", device_id):
            raise HTTPException(status_code=422, detail="Invalid device_id")
        if event_type is not None and event_type not in EVENT_TYPES:
            raise HTTPException(status_code=422, detail="Unsupported event_type")
        return service.storage.query_telemetry(sensor_id=sensor_id, device_id=device_id, event_type=event_type, limit=limit)

    @app.get("/api/v1/telemetry/context")
    def telemetry_context(
        authorization: str | None = Header(default=None),
        device_id: str | None = Query(default=None, min_length=1, max_length=128),
        source_ip: str | None = Query(default=None, min_length=1, max_length=64),
        sensor_id: str | None = Query(default=None, min_length=1, max_length=64),
        event_type: str | None = Query(default=None, min_length=1, max_length=32),
        since: str | None = Query(default=None, min_length=1, max_length=64),
        until: str | None = Query(default=None, min_length=1, max_length=64),
        telemetry_id: str | None = Query(default=None, min_length=1, max_length=128),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, Any]:
        scope = authenticate_query(authorization)
        sensor_id = sensor_scope(scope, sensor_id)
        if device_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,127}", device_id):
            raise HTTPException(status_code=422, detail="Invalid device_id")
        if sensor_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", sensor_id):
            raise HTTPException(status_code=422, detail="Invalid sensor_id")
        if event_type is not None and event_type not in EVENT_TYPES:
            raise HTTPException(status_code=422, detail="Unsupported event_type")
        try:
            if source_ip is not None:
                ipaddress.ip_address(source_ip)
            if since is not None or until is not None:
                resolve_time_range(since, until)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if telemetry_id is not None:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", telemetry_id):
                raise HTTPException(status_code=422, detail="Invalid telemetry_id")
            anchor = service.storage.get_telemetry(telemetry_id)
            if anchor is None:
                raise HTTPException(status_code=404, detail="Telemetry record not found")
            if scope is not None and anchor.sensor_id != scope:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sensor access is limited to its own records")
            sensor_id = sensor_id or anchor.sensor_id
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
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/investigations")
    def investigate_device(
        authorization: str | None = Header(default=None),
        device_id: str = Query(..., min_length=1, max_length=128),
        start: str | None = Query(default=None, min_length=1, max_length=64),
        end: str | None = Query(default=None, min_length=1, max_length=64),
        sensor_id: str | None = Query(default=None, min_length=1, max_length=128),
    ) -> dict[str, Any]:
        scope = authenticate_query(authorization)
        if scope is not None and sensor_id is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sensor ID is required for Edge investigations")
        try:
            device_id = validate_identifier(device_id, field="device_id")
            if sensor_id is not None:
                sensor_id = validate_identifier(sensor_id, field="sensor_id")
                sensor_id = sensor_scope(scope, sensor_id)
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
        authenticate_admin(authorization)
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
        authenticate_admin(authorization)
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
        authenticate_admin(authorization)
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
        authenticate_admin(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        events = service.storage.investigation_events(investigation_id)
        if events is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return {"investigation_id": investigation_id, "events": events}

    @app.post("/api/v1/investigations/{investigation_id}/notes", status_code=status.HTTP_201_CREATED)
    def add_investigation_note(
        investigation_id: str,
        data: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_admin(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            note = validate_analyst_note(data, author="hub-api")
            stored = service.storage.add_investigation_note(investigation_id, note)
        except ValueError as exc:
            code = 409 if "Closed investigations" in str(exc) else 422
            raise HTTPException(status_code=code, detail=str(exc)) from exc
        if stored is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return stored

    @app.get("/api/v1/investigations/{investigation_id}/notes")
    def get_investigation_notes(
        investigation_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_admin(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        notes = service.storage.investigation_notes(investigation_id)
        if notes is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return {"investigation_id": investigation_id, "notes": notes}

    @app.post("/api/v1/investigations/{investigation_id}/actions", status_code=status.HTTP_201_CREATED)
    def add_investigation_action(
        investigation_id: str,
        data: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_admin(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            action = validate_analyst_action(data, author="hub-api")
            stored = service.storage.add_investigation_action(investigation_id, action)
        except ValueError as exc:
            code = 409 if "Closed investigations" in str(exc) else 422
            raise HTTPException(status_code=code, detail=str(exc)) from exc
        if stored is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return stored

    @app.get("/api/v1/investigations/{investigation_id}/actions")
    def get_investigation_actions(
        investigation_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_admin(authorization)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        actions = service.storage.investigation_actions(investigation_id)
        if actions is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return {"investigation_id": investigation_id, "actions": actions}

    @app.patch("/api/v1/investigations/{investigation_id}")
    def update_investigation(
        investigation_id: str,
        data: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate_admin(authorization)
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
        authenticate_admin(authorization)
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
    def get_telemetry(telemetry_id: str = APIPath(..., min_length=1, max_length=128), authorization: str | None = Header(default=None)) -> TelemetryRecord:
        scope = authenticate_query(authorization)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", telemetry_id):
            raise HTTPException(status_code=422, detail="Invalid telemetry_id")
        record = service.storage.get_telemetry(telemetry_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Telemetry record not found")
        if scope is not None and record.sensor_id != scope:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sensor access is limited to its own records")
        return record

    @app.get("/api/v1/edges", response_model=list[EdgeResponse])
    def list_edges(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
        scope = authenticate_query(authorization)
        edges = service.edges()
        if scope is not None:
            edges = [edge for edge in edges if edge.sensor_id == scope]
        return [edge.to_dict() for edge in edges]

    @app.get("/api/v1/edges/{sensor_id}", response_model=EdgeResponse)
    def get_edge(sensor_id: str = APIPath(..., min_length=1, max_length=64), authorization: str | None = Header(default=None)) -> dict[str, Any]:
        scope = authenticate_query(authorization)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", sensor_id):
            raise HTTPException(status_code=422, detail="Invalid sensor_id")
        sensor_id = sensor_scope(scope, sensor_id) or sensor_id
        edge = service.registry.get(sensor_id)
        if edge is None:
            raise HTTPException(status_code=404, detail="Edge sensor not found")
        return edge.to_dict()

    @app.get("/api/v1/stats", response_model=StatsResponse)
    def stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        scope = authenticate_query(authorization)
        if scope is not None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access is required for fleet statistics")
        return service.stats()

    return app
