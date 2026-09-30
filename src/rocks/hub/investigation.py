from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

DEFAULT_WINDOW = timedelta(hours=24)
MAX_WINDOW = timedelta(days=7)
MAX_EVENTS = 1000

_DEVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,127}\Z")
_SENSOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


@dataclass(frozen=True)
class InvestigationEvent:
    timestamp: str
    event_type: str
    device_id: str
    sensor_id: str
    severity: str | None
    title: str
    reason: str | None
    reference_id: str
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_identifier(value: str, *, field: str) -> str:
    pattern = _DEVICE_ID if field == "device_id" else _SENSOR_ID
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"Invalid {field}")
    return value


def parse_timestamp(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"Invalid {field} timestamp; use ISO 8601 with a timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"Invalid {field} timestamp; a timezone is required")
    return parsed.astimezone(timezone.utc)


def utc_string(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    precision = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=precision).replace("+00:00", "Z")


def resolve_time_range(start: str | None, end: str | None) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    end_at = parse_timestamp(end, field="end") if end is not None else now
    start_at = parse_timestamp(start, field="start") if start is not None else end_at - DEFAULT_WINDOW
    if end_at <= start_at:
        raise ValueError("end timestamp must be later than start timestamp")
    if end_at - start_at > MAX_WINDOW:
        raise ValueError("Investigation time window cannot exceed 7 days")
    return utc_string(start_at), utc_string(end_at)