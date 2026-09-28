import logging
import os
from typing import Optional


def get_log_level() -> int:
    level_name = os.getenv("ROCKS_LOG_LEVEL", "INFO").upper()
    return getattr(logging, level_name, logging.INFO)


def configure_logging(level: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger("rocks")
    logger.setLevel(level or get_log_level())
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)

    return logger
