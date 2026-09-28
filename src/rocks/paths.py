from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"


def project_root() -> Path:
    return PROJECT_ROOT


def config_dir() -> Path:
    return CONFIG_DIR


def data_dir() -> Path:
    return DATA_DIR


def log_dir() -> Path:
    return LOG_DIR
