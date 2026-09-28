"""ROCKS Hub central telemetry ingestion package."""

__all__ = ["create_app"]


def create_app(*args, **kwargs):
    from rocks.hub.app import create_app as _create_app

    return _create_app(*args, **kwargs)
