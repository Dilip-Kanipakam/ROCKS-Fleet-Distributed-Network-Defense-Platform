from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from rocks.dashboard.auth import DashboardAuthConfig, create_session, is_authenticated, parse_login_body, verify_password, verify_session
from rocks.dashboard.service import DashboardService
from rocks.hub.investigation import (
    ANALYST_ACTION_CATEGORIES,
    INVESTIGATION_STATUSES,
    parse_timestamp,
    resolve_time_range,
    utc_string,
    validate_analyst_action,
    validate_analyst_note,
    validate_case_text,
    validate_identifier,
    validate_investigation_id,
)


class DashboardRoutes:
    def __init__(self, service: DashboardService, auth_config: DashboardAuthConfig) -> None:
        self.service = service
        self.auth_config = auth_config
        template_dir = Path(__file__).parent / "templates"
        self.templates = Jinja2Templates(directory=str(template_dir))

    def router(self) -> APIRouter:
        router = APIRouter()
        router.add_api_route("/dashboard/login", self.login_page, methods=["GET"])
        router.add_api_route("/dashboard/login", self.login, methods=["POST"])
        router.add_api_route("/dashboard/logout", self.logout, methods=["POST"])
        router.add_api_route("/dashboard", self.dashboard, methods=["GET"])
        router.add_api_route("/dashboard/edges", self.edges_page, methods=["GET"])
        router.add_api_route("/dashboard/telemetry", self.telemetry_page, methods=["GET"])
        router.add_api_route("/dashboard/telemetry/{telemetry_id}", self.telemetry_context_page, methods=["GET"])
        router.add_api_route("/dashboard/events", self.events_page, methods=["GET"])
        router.add_api_route("/dashboard/alerts", self.alerts_page, methods=["GET"])
        router.add_api_route("/dashboard/investigation/{device_id}", self.investigation_page, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/summary", self.summary_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/edges", self.edges_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/telemetry", self.telemetry_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/telemetry/{telemetry_id}/context", self.telemetry_context_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/events", self.events_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/traffic", self.traffic_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/alerts", self.alerts_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/alerts/{alert_id}/acknowledge", self.acknowledge_alert, methods=["POST"])
        router.add_api_route("/api/v1/dashboard/alerts/{alert_id}/resolve", self.resolve_alert, methods=["POST"])
        router.add_api_route("/api/v1/dashboard/investigations", self.create_investigation, methods=["POST"])
        router.add_api_route("/api/v1/dashboard/investigations/{investigation_id}", self.update_investigation, methods=["PATCH"])
        router.add_api_route("/api/v1/dashboard/investigations/{investigation_id}/close", self.close_investigation, methods=["POST"])
        router.add_api_route("/api/v1/dashboard/investigations/{investigation_id}/notes", self.add_investigation_note, methods=["POST"])
        router.add_api_route("/api/v1/dashboard/investigations/{investigation_id}/notes", self.get_investigation_notes, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/investigations/{investigation_id}/actions", self.add_investigation_action, methods=["POST"])
        router.add_api_route("/api/v1/dashboard/investigations/{investigation_id}/actions", self.get_investigation_actions, methods=["GET"])
        return router

    def _page_auth(self, request: Request) -> RedirectResponse | None:
        if not self.auth_config.configured or not is_authenticated(request, self.auth_config):
            return RedirectResponse("/dashboard/login", status_code=status.HTTP_303_SEE_OTHER)
        return None

    def _api_auth(self, request: Request) -> None:
        if not self.auth_config.configured or not is_authenticated(request, self.auth_config):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Dashboard authentication required")

    def login_page(self, request: Request, error: str | None = None):
        if self.auth_config.configured and is_authenticated(request, self.auth_config):
            return RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        return self.templates.TemplateResponse(request=request, name="login.html", context={"error": error, "configured": self.auth_config.configured})

    async def login(self, request: Request):
        username, password = parse_login_body(await request.body())
        if not self.auth_config.configured or username != self.auth_config.username or not verify_password(password, self.auth_config.password_hash):
            return self.templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid credentials.", "configured": self.auth_config.configured}, status_code=401)
        response = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie("rocks_dashboard_session", create_session(username, self.auth_config.session_secret, self.auth_config.session_max_age), max_age=self.auth_config.session_max_age, httponly=True, secure=self.auth_config.cookie_secure, samesite="lax")
        return response

    def logout(self):
        response = RedirectResponse("/dashboard/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie("rocks_dashboard_session")
        return response

    def dashboard(self, request: Request):
        redirect = self._page_auth(request)
        if redirect:
            return redirect
        return self.templates.TemplateResponse(request=request, name="dashboard.html", context={"summary": self.service.summary()})

    def edges_page(self, request: Request):
        redirect = self._page_auth(request)
        if redirect:
            return redirect
        return self.templates.TemplateResponse(request=request, name="edges.html", context={"edges": self.service.edges()})

    def telemetry_page(self, request: Request):
        redirect = self._page_auth(request)
        if redirect:
            return redirect
        return self.templates.TemplateResponse(request=request, name="telemetry.html", context={"telemetry": self.service.telemetry()})

    def telemetry_context_page(self, request: Request, telemetry_id: str):
        redirect = self._page_auth(request)
        if redirect:
            return redirect
        context = self.service.telemetry_context(telemetry_id)
        if context["trigger"] is None:
            raise HTTPException(status_code=404, detail="Telemetry record not found")
        return self.templates.TemplateResponse(request=request, name="telemetry_context.html", context={"context": context})

    def events_page(self, request: Request):
        redirect = self._page_auth(request)
        if redirect:
            return redirect
        return self.templates.TemplateResponse(request=request, name="events.html", context={"events": self.service.events()})

    def alerts_page(self, request: Request):
        redirect = self._page_auth(request)
        if redirect:
            return redirect
        return self.templates.TemplateResponse(request=request, name="alerts.html", context={"alerts": self.service.alerts()})

    def investigation_page(
        self,
        request: Request,
        device_id: str,
        start: str | None = None,
        end: str | None = None,
        at: str | None = None,
        sensor_id: str | None = None,
        case_id: str | None = None,
    ):
        redirect = self._page_auth(request)
        if redirect:
            return redirect
        context: dict[str, Any] = {
            "device_id": device_id,
            "sensor_id": sensor_id,
            "start": start or "",
            "end": end or "",
            "timeline": [],
            "cases": [],
            "alerts": [],
            "selected_case": None,
            "device_found": False,
            "case_id": case_id,
            "action_categories": sorted(ANALYST_ACTION_CATEGORIES),
            "error": None,
        }
        try:
            device_id = validate_identifier(device_id, field="device_id")
            if sensor_id is not None:
                sensor_id = validate_identifier(sensor_id, field="sensor_id")
            if case_id is not None:
                case_id = validate_investigation_id(case_id)
            if at is not None and start is None and end is None:
                center = parse_timestamp(at, field="alert")
                start, end = utc_string(center - timedelta(hours=12)), utc_string(center + timedelta(hours=12))
            start_at, end_at = resolve_time_range(start, end)
            context.update(
                self.service.investigation(
                    device_id,
                    start_at,
                    end_at,
                    sensor_id=sensor_id,
                    case_id=case_id,
                )
            )
            context["case_id"] = case_id or ""
            if case_id and context["selected_case"] is None:
                context["error"] = "Investigation case was not found for this device."
        except ValueError as exc:
            context["error"] = str(exc)
            return self.templates.TemplateResponse(
                request=request,
                name="investigation.html",
                context=context,
                status_code=422,
            )
        except (sqlite3.Error, OSError):
            context["error"] = "Investigation data is temporarily unavailable. Try again later."
            return self.templates.TemplateResponse(
                request=request,
                name="investigation.html",
                context=context,
                status_code=503,
            )
        return self.templates.TemplateResponse(request=request, name="investigation.html", context=context)

    def summary_api(self, request: Request):
        self._api_auth(request)
        return JSONResponse(self.service.summary())

    def edges_api(self, request: Request):
        self._api_auth(request)
        return JSONResponse(self.service.edges())

    def telemetry_api(self, request: Request, limit: int = Query(50, ge=1, le=100), event_type: str | None = None, sensor_id: str | None = None):
        self._api_auth(request)
        return JSONResponse(self.service.telemetry(limit, event_type, sensor_id))

    def telemetry_context_api(self, request: Request, telemetry_id: str, limit: int = Query(50, ge=1, le=100)):
        self._api_auth(request)
        context = self.service.telemetry_context(telemetry_id, limit)
        if context["trigger"] is None:
            raise HTTPException(status_code=404, detail="Telemetry record not found")
        return JSONResponse(context)

    def events_api(self, request: Request, limit: int = Query(50, ge=1, le=100)):
        self._api_auth(request)
        return JSONResponse(self.service.events(limit))

    def traffic_api(self, request: Request, limit: int = Query(20, ge=1, le=100)):
        self._api_auth(request)
        return JSONResponse(self.service.traffic(limit))

    def alerts_api(self, request: Request, limit: int = Query(50, ge=1, le=100)):
        self._api_auth(request)
        return JSONResponse(self.service.alerts(limit))

    def acknowledge_alert(self, request: Request, alert_id: str):
        self._api_auth(request)
        alert = self.service.storage.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        try:
            updated = self.service.storage.update_alert_status(alert_id, "ACKNOWLEDGED")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse({"alert_id": updated.alert_id, "status": updated.status, "message": "Alert acknowledged."})

    def resolve_alert(self, request: Request, alert_id: str):
        self._api_auth(request)
        alert = self.service.storage.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        try:
            updated = self.service.storage.update_alert_status(alert_id, "RESOLVED")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse({"alert_id": updated.alert_id, "status": updated.status, "message": "Alert resolved."})

    async def create_investigation(self, request: Request):
        self._api_auth(request)
        try:
            data = await request.json()
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(status_code=422, detail="Request body must be valid JSON")
        if not isinstance(data, dict) or set(data) - {"title", "description", "device_id", "sensor_id"}:
            raise HTTPException(status_code=422, detail="Invalid investigation request")
        try:
            title = validate_case_text(data.get("title"), field="title", required=True, maximum=200)
            description = validate_case_text(data.get("description", ""), field="description", required=False, maximum=4000)
            device_id = data.get("device_id")
            sensor_id = data.get("sensor_id")
            if device_id is not None:
                device_id = validate_identifier(device_id, field="device_id")
            if sensor_id is not None:
                sensor_id = validate_identifier(sensor_id, field="sensor_id")
            case = self.service.storage.create_investigation(
                title=title,
                description=description,
                device_id=device_id,
                sensor_id=sensor_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="Investigation storage is temporarily unavailable")
        return JSONResponse(case, status_code=status.HTTP_201_CREATED)

    async def update_investigation(self, request: Request, investigation_id: str):
        self._api_auth(request)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            data = await request.json()
        except (ValueError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=422, detail="Invalid investigation request") from exc
        if not isinstance(data, dict) or not data or set(data) - {"title", "description", "status"}:
            raise HTTPException(status_code=422, detail="Provide supported investigation fields")
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
            case = self.service.storage.update_investigation(investigation_id, changes)
        except ValueError as exc:
            conflict = "transition" in str(exc) or "Closed investigations" in str(exc)
            raise HTTPException(status_code=409 if conflict else 422, detail=str(exc)) from exc
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="Investigation storage is temporarily unavailable")
        if case is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return JSONResponse(case)

    def close_investigation(self, request: Request, investigation_id: str):
        self._api_auth(request)
        try:
            investigation_id = validate_investigation_id(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid investigation ID") from exc
        try:
            case = self.service.storage.close_investigation(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="Investigation storage is temporarily unavailable")
        if case is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return JSONResponse(case)

    def _dashboard_author(self, request: Request) -> str:
        author = verify_session(
            request.cookies.get("rocks_dashboard_session"),
            self.auth_config.session_secret,
        )
        return author or "dashboard-admin"

    async def add_investigation_note(self, request: Request, investigation_id: str):
        self._api_auth(request)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            data = await request.json()
            note = validate_analyst_note(data, author=self._dashboard_author(request))
            stored = self.service.storage.add_investigation_note(investigation_id, note)
        except (ValueError, UnicodeDecodeError) as exc:
            conflict = "Closed investigations" in str(exc)
            raise HTTPException(status_code=409 if conflict else 422, detail=str(exc)) from exc
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="Investigation storage is temporarily unavailable")
        if stored is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return JSONResponse(stored, status_code=status.HTTP_201_CREATED)

    def get_investigation_notes(self, request: Request, investigation_id: str):
        self._api_auth(request)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            notes = self.service.storage.investigation_notes(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid investigation ID") from exc
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="Investigation storage is temporarily unavailable")
        if notes is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return JSONResponse({"investigation_id": investigation_id, "notes": notes})

    async def add_investigation_action(self, request: Request, investigation_id: str):
        self._api_auth(request)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            data = await request.json()
            action = validate_analyst_action(data, author=self._dashboard_author(request))
            stored = self.service.storage.add_investigation_action(investigation_id, action)
        except (ValueError, UnicodeDecodeError) as exc:
            conflict = "Closed investigations" in str(exc)
            raise HTTPException(status_code=409 if conflict else 422, detail=str(exc)) from exc
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="Investigation storage is temporarily unavailable")
        if stored is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return JSONResponse(stored, status_code=status.HTTP_201_CREATED)

    def get_investigation_actions(self, request: Request, investigation_id: str):
        self._api_auth(request)
        try:
            investigation_id = validate_investigation_id(investigation_id)
            actions = self.service.storage.investigation_actions(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid investigation ID") from exc
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="Investigation storage is temporarily unavailable")
        if actions is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return JSONResponse({"investigation_id": investigation_id, "actions": actions})
