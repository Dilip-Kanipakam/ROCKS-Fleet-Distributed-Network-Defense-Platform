from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from rocks.dashboard.auth import DashboardAuthConfig, create_session, is_authenticated, parse_login_body, verify_password
from rocks.dashboard.service import DashboardService


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
        router.add_api_route("/api/v1/dashboard/summary", self.summary_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/edges", self.edges_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/telemetry", self.telemetry_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/telemetry/{telemetry_id}/context", self.telemetry_context_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/events", self.events_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/traffic", self.traffic_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/alerts", self.alerts_api, methods=["GET"])
        router.add_api_route("/api/v1/dashboard/alerts/{alert_id}/acknowledge", self.acknowledge_alert, methods=["POST"])
        router.add_api_route("/api/v1/dashboard/alerts/{alert_id}/resolve", self.resolve_alert, methods=["POST"])
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
