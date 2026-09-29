from __future__ import annotations

import getpass
import os
import pwd
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import yaml

from rocks.config import get_config_path, load_config
from rocks.paths import project_root


EDGE_UNIT = "rocks-edge.service"
HUB_UNIT = "rocks-hub.service"
KNOWN_UNITS = (EDGE_UNIT, HUB_UNIT)


class ServiceManagerError(RuntimeError):
    """Raised when system service management cannot complete safely."""


def deployment_units(config: dict[str, Any]) -> tuple[str, ...]:
    mode = str(config.get("deployment", {}).get("mode", ""))
    if mode == "edge":
        return (EDGE_UNIT,)
    if mode == "hub":
        return (HUB_UNIT,)
    if mode == "all-in-one":
        return (EDGE_UNIT, HUB_UNIT)
    raise ServiceManagerError("Configure deployment.mode as edge, hub, or all-in-one before managing services.")


def _systemd_quote(value: str | Path) -> str:
    escaped = str(value).replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _systemd_path(value: str | Path) -> str:
    return str(value).replace("%", "%%").replace("\\", "\\x5c").replace('"', "\\x22").replace(" ", "\\x20")


def _configured_write_directories(config: dict[str, Any], root: Path) -> list[Path]:
    storage = config.get("storage", {})
    ml = config.get("ml", {})
    candidate_values = [
        storage.get("database") or "data/rocks-edge.db",
        storage.get("buffer") or "data/rocks-edge-buffer.db",
        storage.get("hub_database") or "data/rocks-hub.db",
        ml.get("model_path") or "data/ml/rocks_baseline.joblib",
    ]
    directories: set[Path] = set()
    for value in candidate_values:
        path = Path(str(value)).expanduser()
        if not path.is_absolute():
            path = root / path
        directories.add(path.parent.resolve())
    return sorted(directories)


def render_units(
    config: dict[str, Any],
    *,
    config_path: str | Path | None = None,
    application_directory: str | Path | None = None,
    python_executable: str | Path | None = None,
    service_user: str | None = None,
) -> dict[str, str]:
    units = deployment_units(config)
    active_config_path = Path(config_path or get_config_path()).expanduser().resolve()
    root = Path(application_directory or project_root()).resolve()
    python = Path(python_executable or sys.executable).resolve()
    user = service_user or getpass.getuser()
    writable = " ".join(_systemd_path(path) for path in _configured_write_directories(config, root))

    def unit_text(description: str, command: str, *, capture: bool = False) -> str:
        capabilities = ""
        if capture:
            capabilities = "AmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW\n"
        return (
            "[Unit]\n"
            f"Description={description}\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"User={user}\n"
            f"WorkingDirectory={_systemd_path(root)}\n"
            f"Environment=ROCKS_CONFIG_PATH={_systemd_quote(active_config_path)}\n"
            f"ExecStart={_systemd_quote(python)} -m rocks {command}\n"
            "Restart=on-failure\n"
            "RestartSec=5s\n"
            "NoNewPrivileges=true\n"
            "PrivateTmp=true\n"
            "ProtectSystem=full\n"
            f"ReadWritePaths={writable}\n"
            f"{capabilities}"
            "StandardOutput=journal\n"
            "StandardError=journal\n"
            f"SyslogIdentifier={description.lower().replace(' ', '-')}\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

    rendered: dict[str, str] = {}
    if EDGE_UNIT in units:
        rendered[EDGE_UNIT] = unit_text("ROCKS Edge", "edge run", capture=True)
    if HUB_UNIT in units:
        # The dashboard is mounted by the same FastAPI app; do not start a second process.
        rendered[HUB_UNIT] = unit_text("ROCKS Hub and Dashboard", "dashboard run")
    return rendered


def systemd_available() -> bool:
    return shutil.which("systemctl") is not None and Path("/run/systemd/system").is_dir()


def _effective_service_user() -> str:
    sudo_uid = os.getenv("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        return pwd.getpwuid(int(sudo_uid)).pw_name
    return getpass.getuser()


class ServiceManager:
    def __init__(
        self,
        *,
        config_path: str | Path | None = None,
        unit_directory: str | Path = "/etc/systemd/system",
        systemctl: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        systemd_check: Callable[[], bool] = systemd_available,
    ) -> None:
        self.config_path = Path(config_path or get_config_path()).expanduser().resolve()
        self.unit_directory = Path(unit_directory)
        self.systemctl = systemctl or shutil.which("systemctl") or "systemctl"
        self.runner = runner
        self.systemd_check = systemd_check

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            raise ServiceManagerError(
                f"Configuration not found at {self.config_path}; run 'rocks setup' first."
            )
        try:
            permissions = stat.S_IMODE(self.config_path.stat().st_mode)
        except OSError as exc:
            raise ServiceManagerError(f"Unable to inspect config permissions: {exc}") from exc
        if permissions & 0o077:
            raise ServiceManagerError(
                f"Configuration {self.config_path} is readable by group or others; run chmod 600 on it before installing services."
            )
        try:
            config = load_config(self.config_path)
            deployment_units(config)
        except (ValueError, OSError, RuntimeError, yaml.YAMLError) as exc:
            raise ServiceManagerError(f"Unable to load service configuration: {exc}") from exc
        return config

    def generate(self, output_directory: str | Path) -> list[Path]:
        config = self._load_config()
        rendered = render_units(
            config,
            config_path=self.config_path,
            application_directory=project_root(),
            python_executable=sys.executable,
            service_user=_effective_service_user(),
        )
        output = Path(output_directory)
        try:
            output.mkdir(parents=True, exist_ok=True)
            written = []
            for unit_name, contents in rendered.items():
                unit_path = output / unit_name
                unit_path.write_text(contents, encoding="utf-8")
                unit_path.chmod(0o644)
                written.append(unit_path)
        except OSError as exc:
            raise ServiceManagerError(f"Unable to write service unit files: {exc}") from exc
        return written

    def _require_systemd(self) -> None:
        if not self.systemd_check():
            raise ServiceManagerError("systemd is unavailable on this machine; service management requires Linux with an active systemd manager.")

    def _require_root(self) -> None:
        if os.geteuid() != 0:
            raise ServiceManagerError("Installing or removing system services requires administrator privileges. Review the command, then rerun with sudo.")

    def _systemctl(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = self.runner(
                [self.systemctl, *arguments],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise ServiceManagerError(f"Unable to execute systemctl: {exc}") from exc
        if check and result.returncode:
            detail = (result.stderr or result.stdout or "systemctl returned an error").strip()
            raise ServiceManagerError(detail)
        return result

    def install(self) -> list[str]:
        self._require_systemd()
        self._require_root()
        units = deployment_units(self._load_config())
        written = self.generate(self.unit_directory)
        try:
            for unit_name in KNOWN_UNITS:
                if unit_name not in units:
                    self._systemctl("disable", "--now", unit_name, check=False)
                    stale_path = self.unit_directory / unit_name
                    if stale_path.exists():
                        stale_path.unlink()
            self._systemctl("daemon-reload")
            for unit_name in units:
                self._systemctl("enable", "--now", unit_name)
        except ServiceManagerError:
            self._systemctl("daemon-reload", check=False)
            raise
        return [path.name for path in written]

    def uninstall(self) -> list[str]:
        self._require_systemd()
        self._require_root()
        for unit_name in KNOWN_UNITS:
            self._systemctl("disable", "--now", unit_name, check=False)
            unit_path = self.unit_directory / unit_name
            if unit_path.exists():
                unit_path.unlink()
        self._systemctl("daemon-reload")
        return list(KNOWN_UNITS)

    def operate(self, operation: str) -> list[tuple[str, str, str]]:
        self._require_systemd()
        units = deployment_units(self._load_config())
        for unit_name in units:
            if operation in {"start", "restart"} and not (self.unit_directory / unit_name).exists():
                raise ServiceManagerError(f"{unit_name} is not installed; run 'rocks service install' first.")
            self._systemctl(operation, unit_name)
        return self.status()

    def status(self) -> list[tuple[str, str, str]]:
        self._require_systemd()
        units = deployment_units(self._load_config())
        statuses = []
        for unit_name in units:
            result = self._systemctl(
                "show",
                "--no-page",
                "--property=LoadState,ActiveState,SubState,UnitFileState",
                unit_name,
                check=False,
            )
            properties = {}
            for line in result.stdout.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    properties[key] = value
            load_state = properties.get("LoadState", "not-found")
            active = properties.get("ActiveState", "unknown")
            enabled = properties.get("UnitFileState", "unknown")
            if load_state == "not-found":
                active = "not installed"
                enabled = "not installed"
            statuses.append((unit_name, active, enabled))
        return statuses