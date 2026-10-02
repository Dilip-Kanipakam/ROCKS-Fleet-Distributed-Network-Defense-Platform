from __future__ import annotations

import getpass
import os
import pwd
import re
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
    return (
        str(value)
        .replace("%", "%%")
        .replace("\\", "\\x5c")
        .replace('"', "\\x22")
        .replace(" ", "\\s")
    )


def _systemd_environment_file_path(value: str | Path) -> str:
    return str(value).replace("%", "%%").replace("\\", "\\\\").replace(" ", "\\ ")


def _resolve_service_python(
    application_directory: str | Path,
    python_executable: str | Path | None = None,
) -> Path:
    root = Path(application_directory).expanduser().absolute()
    venv_python = root / ".venv" / "bin" / "python"
    if python_executable is not None:
        explicit_python = Path(python_executable).expanduser().absolute()
        if explicit_python == venv_python:
            return venv_python
        raise ServiceManagerError(
            "Systemd services must use the ROCKS installation virtual environment interpreter; "
            f"refusing {explicit_python}."
        )
    if venv_python.is_file():
        return venv_python

    raise ServiceManagerError(
        f"ROCKS services require the installation virtual environment at {venv_python}; "
        "run install-rocks.sh or create the project .venv before installing services."
    )


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


def _ensure_configured_write_directories(config: dict[str, Any], root: Path, service_user: str) -> None:
    try:
        account = pwd.getpwnam(service_user)
    except KeyError as exc:
        raise ServiceManagerError(f"Service account {service_user!r} does not exist.") from exc

    for directory in _configured_write_directories(config, root):
        missing: list[Path] = []
        current = directory
        while not current.exists():
            missing.append(current)
            parent = current.parent
            if parent == current:
                raise ServiceManagerError(f"Unable to find an existing parent for writable directory {directory}.")
            current = parent
        if not current.is_dir():
            raise ServiceManagerError(f"Configured writable path parent is not a directory: {current}.")
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o750)
            for created in reversed(missing):
                os.chown(created, account.pw_uid, account.pw_gid)
                os.chmod(created, 0o750)
        except OSError as exc:
            raise ServiceManagerError(f"Unable to prepare writable directory {directory}: {exc}") from exc


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
    python = _resolve_service_python(root, python_executable)
    user = service_user or getpass.getuser()
    writable = " ".join(_systemd_quote(path) for path in _configured_write_directories(config, root))

    def unit_text(description: str, command: str, *, capture: bool = False) -> str:
        capabilities = ""
        if capture:
            capabilities = "AmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW\n"
        return (
            "[Unit]\n"
            f"Description={description}\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "StartLimitIntervalSec=60s\n"
            "StartLimitBurst=3\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"User={user}\n"
            f"WorkingDirectory={str(root).replace('%', '%%')}\n"
            f"Environment=ROCKS_CONFIG_PATH={_systemd_quote(active_config_path)}\n"
            f"EnvironmentFile=-{_systemd_environment_file_path(root / '.env')}\n"
            f"ExecStart=/usr/bin/env {_systemd_quote(python)} -m rocks {command}\n"
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
        application_directory: str | Path | None = None,
        unit_directory: str | Path = "/etc/systemd/system",
        systemctl: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        systemd_check: Callable[[], bool] = systemd_available,
        proc_root: str | Path = "/proc",
    ) -> None:
        self.config_path = Path(config_path or get_config_path()).expanduser().resolve()
        self.application_directory = Path(application_directory or project_root()).expanduser().resolve()
        self.unit_directory = Path(unit_directory)
        self.systemctl = systemctl or shutil.which("systemctl") or "systemctl"
        self.runner = runner
        self.systemd_check = systemd_check
        self.proc_root = Path(proc_root)

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
            application_directory=self.application_directory,
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
        config = self._load_config()
        units = deployment_units(config)
        service_user = _effective_service_user()
        _ensure_configured_write_directories(config, self.application_directory, service_user)
        previous_contents = {
            unit_name: (self.unit_directory / unit_name).read_text(encoding="utf-8")
            if (self.unit_directory / unit_name).is_file()
            else None
            for unit_name in units
        }
        written = self.generate(self.unit_directory)
        changed_units = {
            path.name
            for path in written
            if previous_contents.get(path.name) != path.read_text(encoding="utf-8")
        }
        try:
            for unit_name in KNOWN_UNITS:
                if unit_name not in units:
                    self._systemctl("disable", "--now", unit_name, check=False)
                    stale_path = self.unit_directory / unit_name
                    if stale_path.exists():
                        stale_path.unlink()
            self._systemctl("daemon-reload")
            for unit_name in units:
                if (
                    unit_name in changed_units
                    and previous_contents.get(unit_name) is not None
                    and self._unit_active(unit_name)
                ):
                    self._systemctl("enable", unit_name)
                    self._systemctl("restart", unit_name)
                else:
                    self._systemctl("enable", "--now", unit_name)
        except ServiceManagerError:
            self._systemctl("daemon-reload", check=False)
            raise
        return [path.name for path in written]

    def _unit_properties(self, unit_name: str) -> dict[str, str]:
        result = self._systemctl(
            "show",
            "--no-page",
            "--property=LoadState,ActiveState,SubState,UnitFileState,ExecStart,User,AmbientCapabilities,CapabilityBoundingSet,MainPID",
            unit_name,
            check=False,
        )
        properties: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value
        return properties

    def _unit_active(self, unit_name: str) -> bool:
        return self._unit_properties(unit_name).get("ActiveState") == "active"

    def verify(self) -> list[tuple[str, dict[str, str]]]:
        self._require_systemd()
        config = self._load_config()
        units = deployment_units(config)
        expected_python = str(_resolve_service_python(self.application_directory))
        expected_user = _effective_service_user()
        verified: list[tuple[str, dict[str, str]]] = []
        for unit_name in units:
            properties = self._unit_properties(unit_name)
            if properties.get("LoadState") != "loaded":
                raise ServiceManagerError(f"{unit_name} is not loaded by systemd.")
            if properties.get("UnitFileState") not in {"enabled", "enabled-runtime"}:
                raise ServiceManagerError(f"{unit_name} is not enabled.")
            if properties.get("ActiveState") != "active" or properties.get("SubState") != "running":
                state = f"{properties.get('ActiveState', 'unknown')}/{properties.get('SubState', 'unknown')}"
                raise ServiceManagerError(f"{unit_name} is not running (state: {state}).")
            exec_start = properties.get("ExecStart", "")
            path_match = re.search(r"(?:^|[\s{;])path=([^;}]+)", exec_start)
            argv_match = re.search(r"(?:^|[;{])\s*argv\[\]=(.+?)(?:\s*;|})", exec_start)
            configured_launcher = path_match.group(1).strip().strip('"') if path_match else ""
            configured_argv = argv_match.group(1) if argv_match else ""
            interpreter_matches = (
                configured_launcher == "/usr/bin/env"
                and configured_argv.startswith(f"/usr/bin/env {expected_python} -m rocks ")
            )
            if not interpreter_matches:
                raise ServiceManagerError(f"{unit_name} is not configured to use the ROCKS virtual environment interpreter.")
            main_pid = properties.get("MainPID", "")
            if not main_pid.isdigit() or int(main_pid) <= 0:
                raise ServiceManagerError(f"{unit_name} has no running main process.")
            try:
                process_argv = (self.proc_root / main_pid / "cmdline").read_bytes().split(b"\0")
                process_python = process_argv[0].decode("utf-8", errors="replace")
            except OSError as exc:
                raise ServiceManagerError(f"Unable to verify the running interpreter for {unit_name}.") from exc
            if process_python != expected_python:
                raise ServiceManagerError(f"{unit_name} process is not running with the ROCKS virtual environment interpreter.")
            if properties.get("User") != expected_user:
                raise ServiceManagerError(f"{unit_name} is not running as the configured non-root service user.")
            if unit_name == EDGE_UNIT:
                for capability_property in ("AmbientCapabilities", "CapabilityBoundingSet"):
                    if "CAP_NET_RAW" not in properties.get(capability_property, "").upper():
                        raise ServiceManagerError(f"{unit_name} is missing required {capability_property}=CAP_NET_RAW.")
            verified.append((unit_name, properties))
        return verified

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
            properties = self._unit_properties(unit_name)
            load_state = properties.get("LoadState", "not-found")
            active = properties.get("ActiveState", "unknown")
            enabled = properties.get("UnitFileState", "unknown")
            if load_state == "not-found":
                active = "not installed"
                enabled = "not installed"
            statuses.append((unit_name, active, enabled))
        return statuses