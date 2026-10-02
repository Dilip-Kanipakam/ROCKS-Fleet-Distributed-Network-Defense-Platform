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


def physical_interfaces(
    interfaces: Iterable[str] | None = None,
    *,
    sysfs_root: str | Path = "/sys/class/net",
) -> list[str]:
    candidates = _available_interfaces() if interfaces is None else interfaces
    virtual_prefixes = ("docker", "br-", "veth", "virbr", "tun", "tap", "wg", "podman", "cni")
    root = Path(sysfs_root)
    selected = []
    for interface in candidates:
        name = str(interface).strip()
        if not name or name == "lo" or name.lower().startswith(virtual_prefixes):
            continue
        interface_path = root / name
        try:
            state = (interface_path / "operstate").read_text(encoding="ascii").strip()
        except OSError:
            continue
        if state == "up" and (interface_path / "device").exists():
            selected.append(name)
    return selected


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
    return f"{service_base_url(host, port)}/dashboard"


def service_base_url(host: str, port: int) -> str:
    normalized_host = host.strip()
    if normalized_host in {"", "0.0.0.0", "::"}:
        normalized_host = "localhost"
    if ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"
    return f"http://{normalized_host}:{port}"


def listener_port_available(host: str, port: int) -> bool:
    normalized_host = host.strip()
    if normalized_host in {"", "0.0.0.0"}:
        family = socket.AF_INET
        address = "0.0.0.0"
    elif normalized_host == "::":
        family = socket.AF_INET6
        address = "::"
    else:
        try:
            address_info = socket.getaddrinfo(normalized_host, port, type=socket.SOCK_STREAM)
        except OSError:
            return False
        if not address_info:
            return False
        family, _, _, _, sockaddr = address_info[0]
        address = sockaddr[0]

    try:
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.bind((address, port))
    except OSError:
        return False
    return True