from __future__ import annotations

import socket
import sys
from pathlib import Path
from typing import Iterable


MINIMUM_PYTHON_VERSION = (3, 10)


def detect_platform(platform: str | None = None) -> str:
    normalized = (platform or sys.platform).lower()
    if normalized.startswith("linux"):
        return "linux"
    return "unsupported"


def python_version_supported(version: tuple[int, ...] | None = None) -> bool:
    candidate = version or sys.version_info[:3]
    major, minor = candidate[:2]
    return (major, minor) >= MINIMUM_PYTHON_VERSION


def interface_choice(interfaces: Iterable[str] | None = None, *, preferred: str | None = None) -> str:
    candidates = _available_interfaces() if interfaces is None else interfaces
    names = [str(item).strip() for item in candidates if str(item).strip()]
    if not names:
        raise ValueError("No network interfaces are available for Edge setup.")
    if preferred and preferred in names:
        return preferred

    non_loopback = [name for name in names if name.lower() not in {"lo", "lo0"}]
    if non_loopback:
        return non_loopback[0]
    return names[0]


def _available_interfaces() -> list[str]:
    try:
        return [name for _, name in socket.if_nameindex()]
    except OSError:
        return []


def redact_secret(value: str | None, *, keep_tail: int = 2) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if len(text) <= keep_tail + 2:
        return "*" * len(text)
    prefix = text[:2]
    suffix = text[-keep_tail:]
    masked = "*" * max(0, len(text) - len(prefix) - len(suffix))
    return f"{prefix}{masked}{suffix}"


def service_install_command(
    sudo_executable: str,
    python_executable: str,
    config_path: str | Path,
) -> list[str]:
    return [
        sudo_executable,
        "env",
        f"ROCKS_CONFIG_PATH={Path(config_path).expanduser().resolve()}",
        python_executable,
        "-m",
        "rocks",
        "service",
        "install",
    ]


def dashboard_url(host: str, port: int) -> str:
    normalized_host = host.strip()
    if normalized_host in {"", "0.0.0.0", "::"}:
        normalized_host = "localhost"
    if ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"
    return f"http://{normalized_host}:{port}/dashboard"