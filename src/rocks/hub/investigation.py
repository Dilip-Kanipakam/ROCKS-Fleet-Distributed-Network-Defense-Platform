from __future__ import annotations

import re
import json
import math
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

DEFAULT_WINDOW = timedelta(hours=24)
MAX_WINDOW = timedelta(days=7)
MAX_EVENTS = 1000
INVESTIGATION_STATUSES = {"OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"}
INVESTIGATION_TRANSITIONS = {
    "OPEN": {"IN_PROGRESS"},
    "IN_PROGRESS": {"RESOLVED"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": set(),
}
CASE_EVENT_TYPES = {
    "ANALYST_NOTE",
    "ANALYST_ACTION",
    "DETECTION",
    "ALERT",
    "TELEMETRY",
    "BEHAVIOR_SUMMARY",
    "ML_ANALYSIS",
}
ANALYST_ACTION_CATEGORIES = {
    "OBSERVED",
    "INVESTIGATING",
    "DEVICE_REVIEWED",
    "TRAFFIC_REVIEWED",
    "ADMIN_ACTION_REQUIRED",
    "RESOLVED",
}
MAX_ANALYST_NOTE_LENGTH = 2000
_SECRET_KEY = re.compile(r"password|passwd|smtp|api.?key|token|session.?secret|authorization|credential", re.IGNORECASE)
_SENSITIVE_NOTE = re.compile(
    r"(?:\b(?:password|passwd|api[ _-]?key|token|cookie|authorization|session[ _-]?secret|smtp[ _-]?(?:password|credential))\b\s*[:=]|\bbearer\s+\S+)",
    re.IGNORECASE,
)

_DEVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,127}\Z")
_SENSOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")


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


@dataclass(frozen=True)
class CaseTimelineEvent:
    event_id: str
    investigation_id: str
    timestamp: str
    event_type: str
    severity: str | None
    message: str
    source: str
    metadata: dict[str, Any]

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


def validate_investigation_id(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (AttributeError, ValueError) as exc:
        raise ValueError("Invalid investigation ID") from exc


def validate_case_text(value: Any, *, field: str, required: bool, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    normalized = value.strip()
    if required and not normalized:
        raise ValueError(f"{field} is required")
    if len(normalized) > maximum:
        raise ValueError(f"{field} must be at most {maximum} characters")
    return normalized


def validate_case_event(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Event body must be an object")
    allowed = {"timestamp", "event_type", "severity", "message", "source", "metadata"}
    unexpected = set(data) - allowed
    if unexpected:
        raise ValueError("Event contains unsupported fields")
    event_type = data.get("event_type")
    if not isinstance(event_type, str) or event_type not in CASE_EVENT_TYPES:
        raise ValueError("event_type must be one of: " + ", ".join(sorted(CASE_EVENT_TYPES)))
    severity = data.get("severity")
    if severity is not None and (
        not isinstance(severity, str)
        or severity not in {"INFO", "LOW", "MEDIUM", "WARNING", "HIGH", "CRITICAL"}
    ):
        raise ValueError("Invalid event severity")
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    _validate_metadata(metadata)
    encoded_metadata = json.dumps(metadata, allow_nan=False, separators=(",", ":"))
    if len(encoded_metadata.encode("utf-8")) > 8192:
        raise ValueError("metadata must be no larger than 8192 bytes")
    timestamp = data.get("timestamp")
    if timestamp is None:
        normalized_timestamp = _utc_now()
    else:
        normalized_timestamp = utc_string(parse_timestamp(timestamp, field="event"))
    source = validate_case_text(data.get("source", "analyst"), field="source", required=True, maximum=80)
    message = validate_case_text(data.get("message"), field="message", required=True, maximum=2000)
    if event_type in {"ANALYST_NOTE", "ANALYST_ACTION"}:
        _validate_analyst_text(message)
    if event_type == "ANALYST_ACTION":
        category = metadata.get("category")
        if not isinstance(category, str) or category not in ANALYST_ACTION_CATEGORIES:
            raise ValueError("Invalid analyst action category")
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": normalized_timestamp,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "source": source,
        "metadata": metadata,
    }


def validate_analyst_note(data: Any, *, author: str) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) - {"note_text", "category"}:
        raise ValueError("Note body must contain note_text and optional category")
    note_text = validate_case_text(
        data.get("note_text"),
        field="note_text",
        required=True,
        maximum=MAX_ANALYST_NOTE_LENGTH,
    )
    _validate_analyst_text(note_text)
    category = data.get("category")
    if category is not None and (
        not isinstance(category, str) or category not in ANALYST_ACTION_CATEGORIES
    ):
        raise ValueError("Invalid analyst note category")
    safe_author = validate_case_text(author, field="author", required=False, maximum=80)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _utc_now(),
        "event_type": "ANALYST_NOTE",
        "severity": "INFO",
        "message": note_text,
        "source": safe_author or "dashboard-admin",
        "metadata": {"category": category} if category is not None else {},
    }


def validate_analyst_action(data: Any, *, author: str) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) - {"category", "message"}:
        raise ValueError("Action body must contain category and optional message")
    category = data.get("category")
    if not isinstance(category, str) or category not in ANALYST_ACTION_CATEGORIES:
        raise ValueError("Invalid analyst action category")
    message = data.get("message", f"Analyst recorded {category}.")
    message = validate_case_text(message, field="message", required=True, maximum=500)
    _validate_analyst_text(message)
    safe_author = validate_case_text(author, field="author", required=False, maximum=80)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _utc_now(),
        "event_type": "ANALYST_ACTION",
        "severity": "INFO",
        "message": message,
        "source": safe_author or "dashboard-admin",
        "metadata": {"category": category},
    }


def _validate_metadata(value: Any, *, depth: int = 0) -> None:
    if depth > 5:
        raise ValueError("metadata nesting cannot exceed 5 levels")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or _SECRET_KEY.search(key):
                raise ValueError("metadata contains a forbidden key")
            _validate_metadata(item, depth=depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _validate_metadata(item, depth=depth + 1)
        return
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    raise ValueError("metadata must contain only JSON values")


def _validate_analyst_text(value: str) -> None:
    if _SENSITIVE_NOTE.search(value):
        raise ValueError("Analyst text contains credential-like content")
    if value.lstrip().startswith(("{", "[")):
        try:
            json.loads(value)
        except json.JSONDecodeError:
            pass
        else:
            raise ValueError("Structured payload content is not accepted in analyst text")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def resolve_time_range(start: str | None, end: str | None) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    end_at = parse_timestamp(end, field="end") if end is not None else now
    start_at = parse_timestamp(start, field="start") if start is not None else end_at - DEFAULT_WINDOW
    if end_at <= start_at:
        raise ValueError("end timestamp must be later than start timestamp")
    if end_at - start_at > MAX_WINDOW:
        raise ValueError("Investigation time window cannot exceed 7 days")
    return utc_string(start_at), utc_string(end_at)