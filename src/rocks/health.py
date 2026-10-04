from __future__ import annotations

import math
import os
import sqlite3
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import quote, urlsplit, urlunsplit

import yaml

from rocks.config import get_buffer_path, get_config_path, get_hub_path, get_storage_path, load_config, validate_positive_integer
from rocks.paths import project_root
from rocks.service_manager import EDGE_UNIT, HUB_UNIT, ServiceManager, ServiceManagerError


class HealthStatus(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


@dataclass(frozen=True)
class HealthCheck:
    name: str
    status: HealthStatus
    message: str
    required: bool = True
    details: dict[str, str | int | float | bool] = field(default_factory=dict)
    hint: str = ""


@dataclass(frozen=True)
class HealthReport:
    checks: tuple[HealthCheck, ...]
    overall: HealthStatus
    deployment_mode: str = "unknown"
    config_path: str = ""

    def get(self, name: str) -> HealthCheck:
        return next(check for check in self.checks if check.name == name)

    @property
    def exit_code(self) -> int:
        if self.get("configuration").status == HealthStatus.ERROR:
            return 2
        return 0 if self.overall == HealthStatus.HEALTHY else 1


def aggregate_health(statuses: list[HealthStatus]) -> HealthStatus:
    relevant = [status for status in statuses if status != HealthStatus.NOT_APPLICABLE]
    if HealthStatus.ERROR in relevant:
        return HealthStatus.UNHEALTHY
    if HealthStatus.WARNING in relevant:
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _configured_path(config: dict[str, Any], key: str, default: Path) -> Path:
    raw_path = config.get("storage", {}).get(key)
    path = Path(str(raw_path)).expanduser() if raw_path else default
    if not path.is_absolute():
        path = project_root() / path
    return path.resolve()


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    uri = f"file:{quote(str(path.resolve()))}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=1.0)
    try:
        yield connection
    finally:
        connection.close()


def _redacted_url(value: str) -> str:
    parts = urlsplit(value)
    hostname = parts.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        port = ""
    return urlunsplit((parts.scheme, hostname + port, parts.path, "", ""))


def _probe_sqlite(
    path: Path,
    *,
    table: str,
    freshness_seconds: int,
    now: datetime,
    timestamp_column: str = "timestamp",
) -> dict[str, Any]:
    if timestamp_column not in {"timestamp", "received_at"}:
        raise ValueError("Unsupported telemetry freshness timestamp column")
    cutoff = (now - timedelta(seconds=freshness_seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with _readonly_connection(path) as connection:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("SELECT 1").fetchone()
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if not exists:
            raise sqlite3.DatabaseError(f"Required {table} table is missing")
        columns = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}
        if timestamp_column not in columns:
            raise sqlite3.DatabaseError(f"Required {timestamp_column} column is missing from {table}")
        recent_count = int(
            connection.execute(
                f"SELECT COUNT(*) FROM (SELECT 1 FROM {table} WHERE {timestamp_column} >= ? LIMIT 1001)",
                (cutoff,),
            ).fetchone()[0]
        )
        latest_row = connection.execute(f"SELECT MAX({timestamp_column}) FROM {table}").fetchone()
        latest = str(latest_row[0]) if latest_row and latest_row[0] else None
        return {"recent_count": recent_count, "latest_timestamp": latest}


class HealthChecker:
    def __init__(
        self,
        *,
        config_path: str | Path | None = None,
        service_manager: Any | None = None,
        http_get: Callable[[str, float], Any] | None = None,
        now: Callable[[], datetime] = _now_utc,
    ) -> None:
        self.config_path = Path(config_path or get_config_path()).expanduser().resolve()
        self.service_manager = service_manager or ServiceManager(config_path=self.config_path)
        self.http_get = http_get or self._http_get
        self.now = now

    @staticmethod
    def _http_get(url: str, timeout: float) -> Any:
        return urllib.request.urlopen(url, timeout=timeout)

    def run(self) -> HealthReport:
        checks: list[HealthCheck] = []
        try:
            if not self.config_path.is_file():
                raise FileNotFoundError(self.config_path)
            if self.config_path.stat().st_mode & 0o077:
                raise ValueError("configuration file permissions must be owner-only (chmod 600)")
            config = load_config(self.config_path)
            mode = str(config.get("deployment", {}).get("mode", ""))
            self._validate_config(config, mode)
        except FileNotFoundError as exc:
            checks.append(
                HealthCheck(
                    "configuration",
                    HealthStatus.ERROR,
                    f"Configuration file is unavailable: {exc.filename or self.config_path}",
                    hint="Run 'rocks setup' or correct the YAML configuration, then run 'rocks setup --check'.",
                )
            )
            return HealthReport(tuple(checks), HealthStatus.UNHEALTHY, config_path=str(self.config_path))
        except yaml.YAMLError as exc:
            checks.append(
                HealthCheck(
                    "configuration",
                    HealthStatus.ERROR,
                    f"Configuration YAML cannot be parsed ({type(exc).__name__}).",
                    hint="Correct the YAML syntax, then run 'rocks setup --check'.",
                )
            )
            return HealthReport(tuple(checks), HealthStatus.UNHEALTHY, config_path=str(self.config_path))
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
            checks.append(
                HealthCheck(
                    "configuration",
                    HealthStatus.ERROR,
                    f"Configuration is invalid ({type(exc).__name__}: {exc}).",
                    hint="Run 'rocks setup' or correct the YAML configuration, then run 'rocks setup --check'.",
                )
            )
            return HealthReport(tuple(checks), HealthStatus.UNHEALTHY, config_path=str(self.config_path))

        checks.append(
            HealthCheck(
                "configuration",
                HealthStatus.OK,
                "Configuration loaded and required sections are valid.",
                details={
                    "config_path": str(self.config_path),
                    "deployment_mode": mode,
                    **({"sensor_id": config["edge"].get("sensor_id", "")} if mode in {"edge", "all-in-one"} else {}),
                },
            )
        )

        edge_enabled = mode in {"edge", "all-in-one"}
        hub_enabled = mode in {"hub", "all-in-one"}
        service_states = self._service_states()
        checks.append(self._service_check("edge_service", EDGE_UNIT, edge_enabled, service_states, "rocks service status; journalctl -u rocks-edge.service"))
        checks.append(self._service_check("hub_service", HUB_UNIT, hub_enabled, service_states, "rocks service status; journalctl -u rocks-hub.service"))

        if edge_enabled:
            edge_path = _configured_path(config, "database", get_storage_path(self.config_path))
            edge_buffer_path = _configured_path(config, "buffer", get_buffer_path(self.config_path))
            checks.append(
                self._storage_check(
                    "edge_storage",
                    edge_path,
                    "telemetry",
                    "Check storage.database and 'journalctl -u rocks-edge.service'.",
                )
            )
            checks.append(self._buffer_check(edge_buffer_path))
        else:
            checks.append(HealthCheck("edge_storage", HealthStatus.NOT_APPLICABLE, "Edge is not configured on this host.", required=False))
            checks.append(HealthCheck("edge_buffer", HealthStatus.NOT_APPLICABLE, "Edge is not configured on this host.", required=False))

        if hub_enabled:
            hub_path = _configured_path(config, "hub_database", get_hub_path(self.config_path))
            checks.append(self._hub_database_check(hub_path))
            dashboard_config = config.get("dashboard", {})
            api_base = _local_endpoint(
                str(dashboard_config.get("host", "127.0.0.1")),
                int(dashboard_config.get("port", 8000)),
            )
            checks.append(self._endpoint_check("hub_api", f"{api_base}/api/v1/health", "rocks hub status"))
            if config.get("dashboard", {}).get("enabled", True):
                checks.append(self._endpoint_check("dashboard", f"{api_base}/dashboard/login", "rocks service status; journalctl -u rocks-hub.service"))
            else:
                checks.append(HealthCheck("dashboard", HealthStatus.NOT_APPLICABLE, "Dashboard is disabled in configuration.", required=False))
            checks.append(self._alerts_check(hub_path, config))
        else:
            checks.extend(
                [
                    HealthCheck("hub_database", HealthStatus.NOT_APPLICABLE, "Hub is not configured on this host.", required=False),
                    HealthCheck("dashboard", HealthStatus.NOT_APPLICABLE, "Dashboard is not configured on this host.", required=False),
                    HealthCheck("alerts", HealthStatus.NOT_APPLICABLE, "Hub alert storage is not configured on this host.", required=False),
                ]
            )
            remote_hub = _redacted_url(str(os.getenv("ROCKS_HUB_URL", config.get("edge", {}).get("hub_url", ""))).rstrip("/"))
            checks.append(self._endpoint_check("hub_api", f"{remote_hub}/api/v1/health", "rocks edge test-hub"))

        telemetry_path = (
            _configured_path(config, "hub_database", get_hub_path(self.config_path))
            if hub_enabled
            else _configured_path(config, "database", get_storage_path(self.config_path))
        )
        checks.append(
            self._telemetry_check(
                telemetry_path,
                config,
                timestamp_column="received_at" if hub_enabled else "timestamp",
            )
        )

        effective_statuses = [
            HealthStatus.WARNING if check.required and check.status == HealthStatus.UNKNOWN else check.status
            for check in checks
        ]
        overall = aggregate_health(effective_statuses)
        return HealthReport(tuple(checks), overall, mode, str(self.config_path))

    @staticmethod
    def _validate_config(config: dict[str, Any], mode: str) -> None:
        if mode not in {"edge", "hub", "all-in-one"}:
            raise ValueError("deployment.mode must be edge, hub, or all-in-one")
        for section in ("deployment", "edge", "hub", "telemetry", "storage", "dashboard", "alerts"):
            if not isinstance(config.get(section), dict):
                raise ValueError(f"configuration section '{section}' must be a mapping")
        if "health" in config and not isinstance(config["health"], dict):
            raise ValueError("configuration section 'health' must be a mapping")
        freshness = config.get("health", {}).get("telemetry_freshness_seconds", 300)
        if isinstance(freshness, bool) or not isinstance(freshness, (int, float)) or freshness <= 0 or not math.isfinite(freshness):
            raise ValueError("health.telemetry_freshness_seconds must be a positive finite number")
        if mode in {"edge", "all-in-one"}:
            edge = config["edge"]
            buffer_limit = edge.get("buffer_limit", 10_000)
            if isinstance(buffer_limit, bool) or not isinstance(buffer_limit, int) or buffer_limit <= 0:
                raise ValueError("edge.buffer_limit must be a positive integer")
            validate_positive_integer(edge.get("max_active_flows", 10_000), field="edge.max_active_flows")
            window_seconds = config["telemetry"].get("window_seconds", 60)
            if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)) or not math.isfinite(window_seconds) or window_seconds <= 0:
                raise ValueError("telemetry.window_seconds must be a positive finite number")
            if not str(os.getenv("ROCKS_SENSOR_ID", edge.get("sensor_id", ""))).strip():
                raise ValueError("edge.sensor_id is required")
            if not str(os.getenv("ROCKS_INTERFACE", edge.get("interface", ""))).strip():
                raise ValueError("edge.interface is required")
            hub_url = os.getenv("ROCKS_HUB_URL", str(edge.get("hub_url", config["hub"].get("url", "")))).strip()
            _validate_http_url(hub_url, "Edge Hub URL")
            if not os.getenv("ROCKS_API_KEY", str(config["hub"].get("api_key", ""))).strip():
                raise ValueError("an Edge API key is required")
            try:
                send_interval = float(edge.get("send_interval_seconds", 5))
            except (TypeError, ValueError) as exc:
                raise ValueError("edge.send_interval_seconds must be a positive finite number") from exc
            if not math.isfinite(send_interval) or send_interval <= 0:
                raise ValueError("edge.send_interval_seconds must be a positive finite number")
        if mode in {"hub", "all-in-one"}:
            hub = config["hub"]
            port = hub.get("port", 8000)
            try:
                port = int(port)
            except (TypeError, ValueError) as exc:
                raise ValueError("hub.port must be an integer from 1 to 65535") from exc
            if not 1 <= port <= 65535:
                raise ValueError("hub.port must be an integer from 1 to 65535")
            hub_url = os.getenv("ROCKS_HUB_URL", str(hub.get("url") or f"http://127.0.0.1:{port}")).strip()
            _validate_http_url(hub_url, "Hub URL")
            dashboard = config["dashboard"]
            if not dashboard.get("enabled", True):
                raise ValueError("dashboard.enabled must be true for Hub deployment")
            try:
                dashboard_port = int(dashboard.get("port", 8000))
            except (TypeError, ValueError) as exc:
                raise ValueError("dashboard.port must be an integer from 1 to 65535") from exc
            if not 1 <= dashboard_port <= 65535 or not str(dashboard.get("host", "127.0.0.1")).strip():
                raise ValueError("dashboard host/port must be valid")
            if not os.getenv("ROCKS_ADMIN_USERNAME", str(dashboard.get("admin_username", ""))).strip():
                raise ValueError("a dashboard administrator username is required")
            if not os.getenv("ROCKS_ADMIN_PASSWORD_HASH", str(dashboard.get("admin_password_hash", ""))).strip():
                raise ValueError("a dashboard administrator password hash is required")
            if not os.getenv("ROCKS_SESSION_SECRET", str(dashboard.get("session_secret", ""))).strip():
                raise ValueError("a dashboard session secret is required")
        alerts = config["alerts"]
        if not isinstance(alerts.get("enabled", True), bool):
            raise ValueError("alerts.enabled must be true or false")
        for threshold_name in ("anomaly_threshold", "high_retention_threshold"):
            threshold = alerts.get(threshold_name, 0.70)
            if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError(f"alerts.{threshold_name} must be a finite number between 0 and 1")


    def _service_states(self) -> dict[str, tuple[str, str] | None]:
        self._service_error = "systemd status is unavailable"
        try:
            return {name: (active, enabled) for name, active, enabled in self.service_manager.status()}
        except (OSError, RuntimeError, ServiceManagerError) as exc:
            self._service_error = type(exc).__name__
            return {}

    def _service_check(
        self,
        name: str,
        unit: str,
        applicable: bool,
        states: dict[str, tuple[str, str] | None],
        hint: str,
    ) -> HealthCheck:
        if not applicable:
            return HealthCheck(name, HealthStatus.NOT_APPLICABLE, "Service is not required for this deployment mode.", required=False)
        if unit not in states:
            error = getattr(self, "_service_error", "systemd status is unavailable")
            return HealthCheck(name, HealthStatus.UNKNOWN, f"Service state is unavailable: {error}", hint=hint)
        active, enabled = states[unit]
        if active == "active":
            return HealthCheck(name, HealthStatus.OK, "Service is running.", details={"unit": unit, "active": active, "enabled": enabled})
        if active == "failed":
            return HealthCheck(name, HealthStatus.ERROR, "Service has failed.", details={"unit": unit, "active": active, "enabled": enabled}, hint=hint)
        if active == "not installed":
            return HealthCheck(name, HealthStatus.WARNING, "Service is not installed.", details={"unit": unit, "active": active, "enabled": enabled}, hint="Run 'rocks service install'.")
        if active == "inactive":
            return HealthCheck(name, HealthStatus.WARNING, "Service is stopped.", details={"unit": unit, "active": active, "enabled": enabled}, hint="Run 'rocks service status' and 'rocks service start'.")
        return HealthCheck(name, HealthStatus.WARNING, f"Service is {active}.", details={"unit": unit, "active": active, "enabled": enabled}, hint="Run 'rocks service status' and 'rocks service start'.")

    def _endpoint_check(self, name: str, url: str, hint: str) -> HealthCheck:
        if not url.startswith(("http://", "https://")):
            return HealthCheck(name, HealthStatus.ERROR, "Endpoint URL is not configured correctly.", hint=hint)
        try:
            with self.http_get(url, 2.0) as response:
                if 200 <= int(response.status) < 400:
                    return HealthCheck(name, HealthStatus.OK, "Endpoint is reachable.", details={"url": _redacted_url(url)})
                return HealthCheck(name, HealthStatus.WARNING, f"Endpoint returned HTTP {response.status}.", details={"url": _redacted_url(url)}, hint=hint)
        except (OSError, TimeoutError, urllib.error.URLError, ValueError) as exc:
            return HealthCheck(name, HealthStatus.WARNING, f"Endpoint is unavailable: {type(exc).__name__}.", details={"url": _redacted_url(url)}, hint=hint)

    def _storage_check(self, name: str, path: Path, table: str, hint: str) -> HealthCheck:
        try:
            with _readonly_connection(path) as connection:
                connection.execute("PRAGMA query_only = ON")
                connection.execute("SELECT 1").fetchone()
                if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    raise sqlite3.DatabaseError(f"Required {table} table is missing")
            return HealthCheck(name, HealthStatus.OK, "SQLite storage is readable.", details={"path": str(path)})
        except (OSError, sqlite3.Error) as exc:
            return HealthCheck(name, HealthStatus.ERROR, f"SQLite storage is unavailable: {exc}", details={"path": str(path)}, hint=hint)

    def _buffer_check(self, path: Path) -> HealthCheck:
        try:
            with _readonly_connection(path) as connection:
                connection.execute("PRAGMA query_only = ON")
                count = int(connection.execute("SELECT COUNT(*) FROM (SELECT 1 FROM buffer LIMIT 1001)").fetchone()[0])
                stats_table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='buffer_stats'"
                ).fetchone()
                dropped, dropped_packets = (0, 0)
                if stats_table:
                    columns = {row[1] for row in connection.execute("PRAGMA table_info(buffer_stats)")}
                    row = connection.execute(
                        "SELECT dropped_records, dropped_packets FROM buffer_stats WHERE id = 1"
                        if "dropped_packets" in columns
                        else "SELECT dropped_records, 0 FROM buffer_stats WHERE id = 1"
                    ).fetchone()
                    if row:
                        dropped, dropped_packets = int(row[0]), int(row[1])
            label = "1000+" if count > 1000 else str(count)
            details = {
                "path": str(path),
                "records_capped": count,
                "dropped_records": dropped,
                "dropped_packets": dropped_packets,
            }
            if dropped or dropped_packets:
                return HealthCheck(
                    "edge_buffer",
                    HealthStatus.WARNING,
                    f"Edge buffer is readable ({label} records), but {dropped} telemetry records and {dropped_packets} packet summaries were dropped.",
                    details=details,
                    hint="Restore sender throughput or reduce telemetry generation; inspect EDGE_BUFFER_OVERFLOW logs.",
                )
            return HealthCheck("edge_buffer", HealthStatus.OK, f"Edge buffer is readable ({label} records).", details=details)
        except (OSError, sqlite3.Error) as exc:
            return HealthCheck("edge_buffer", HealthStatus.WARNING, f"Edge buffer is unavailable: {exc}", details={"path": str(path)}, hint="Check Edge storage permissions and 'journalctl -u rocks-edge.service'.")

    def _hub_database_check(self, path: Path) -> HealthCheck:
        try:
            with _readonly_connection(path) as connection:
                connection.execute("PRAGMA query_only = ON")
                connection.execute("SELECT 1").fetchone()
                for table in ("telemetry", "alerts"):
                    if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                        raise sqlite3.DatabaseError(f"Required {table} table is missing")
                recent_alerts = int(connection.execute("SELECT COUNT(*) FROM (SELECT 1 FROM alerts ORDER BY timestamp DESC LIMIT 20)").fetchone()[0])
            return HealthCheck("hub_database", HealthStatus.OK, "Hub SQLite database is readable.", details={"path": str(path), "recent_alerts_sample": recent_alerts})
        except (OSError, sqlite3.Error) as exc:
            return HealthCheck("hub_database", HealthStatus.ERROR, f"Hub SQLite database is unavailable: {exc}", details={"path": str(path)}, hint="Check the configured storage.hub_database path and 'journalctl -u rocks-hub.service'.")

    def _alerts_check(self, path: Path, config: dict[str, Any]) -> HealthCheck:
        if not config.get("alerts", {}).get("enabled", True):
            return HealthCheck("alerts", HealthStatus.NOT_APPLICABLE, "Alert generation is disabled.", required=False)
        database_check = self._hub_database_check(path)
        return HealthCheck("alerts", database_check.status, "Alert storage is available." if database_check.status == HealthStatus.OK else "Alert storage is unavailable.", details={"recent_alerts_sample": database_check.details.get("recent_alerts_sample", 0)}, hint=database_check.hint)

    def _telemetry_check(
        self,
        path: Path,
        config: dict[str, Any],
        *,
        timestamp_column: str,
    ) -> HealthCheck:
        health_config = config.get("health", {})
        try:
            freshness_seconds = int(health_config.get("telemetry_freshness_seconds", 300))
        except (TypeError, ValueError):
            return HealthCheck("telemetry", HealthStatus.ERROR, "health.telemetry_freshness_seconds must be a positive integer.")
        if freshness_seconds <= 0:
            return HealthCheck("telemetry", HealthStatus.ERROR, "health.telemetry_freshness_seconds must be a positive integer.")
        table = "telemetry"
        try:
            result = _probe_sqlite(
                path,
                table=table,
                freshness_seconds=freshness_seconds,
                now=self.now(),
                timestamp_column=timestamp_column,
            )
        except (OSError, sqlite3.Error) as exc:
            return HealthCheck("telemetry", HealthStatus.ERROR, f"Unable to inspect telemetry storage: {exc}", hint="Check the database check above and verify the configured Edge or Hub SQLite path.")
        timestamp = result["latest_timestamp"]
        parsed = _parse_timestamp(timestamp)
        if parsed is None:
            return HealthCheck("telemetry", HealthStatus.WARNING, "No telemetry has been received.", details={"recent_count_capped": result["recent_count"], "freshness_seconds": freshness_seconds, "freshness_basis": timestamp_column}, hint="Verify the Edge service, observation interface, SPAN/TAP visibility, and Hub connectivity.")
        age_seconds = max(0, int((self.now() - parsed).total_seconds()))
        if age_seconds <= freshness_seconds:
            return HealthCheck("telemetry", HealthStatus.OK, "Recent telemetry is present.", details={"recent_count_capped": result["recent_count"], "age_seconds": age_seconds, "freshness_seconds": freshness_seconds, "freshness_basis": timestamp_column})
        return HealthCheck("telemetry", HealthStatus.WARNING, "Telemetry is stale.", details={"recent_count_capped": result["recent_count"], "age_seconds": age_seconds, "freshness_seconds": freshness_seconds, "freshness_basis": timestamp_column}, hint="Verify Edge observation interface and SPAN/TAP configuration, then check Edge-to-Hub connectivity.")


def _validate_http_url(value: str, label: str) -> None:
    try:
        parsed = urlsplit(value)
        valid_host = parsed.hostname is not None
        valid_scheme = parsed.scheme in {"http", "https"}
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not valid_scheme or not valid_host or (port is not None and not 1 <= port <= 65535):
        raise ValueError(f"{label} must be a valid http(s) URL")


def _local_endpoint(host: str, port: int) -> str:
    if host in {"0.0.0.0", "::", ""}:
        host = "127.0.0.1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port}"
