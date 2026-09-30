# Investigation API

The Hub provides two complementary read/write surfaces under `/api/v1/investigations`:

- `GET /api/v1/investigations?device_id=...` is the existing read-only ROCKS evidence timeline, bounded to one exact device and time range.
- `POST /api/v1/investigations` and the `/{investigation_id}` routes manage analyst cases and their append-only case timelines.

They share the URL prefix but have distinct HTTP methods and purposes. A case may optionally record a `device_id` and `sensor_id`; analysts can attach references to existing detection, telemetry, ML, or alert records as event metadata. Case events are not automatically copied from the device evidence query.

## Authentication

All endpoints require the existing Hub bearer API key in `Authorization`. The key must belong to a registered edge sensor. Missing or invalid credentials return `401 Unauthorized`.

## Case lifecycle

Cases begin in `OPEN`. Allowed status transitions are:

```text
OPEN -> IN_PROGRESS -> RESOLVED -> CLOSED
```

`PATCH` records a status change in the case timeline. `POST /{investigation_id}/close` is the explicit close operation and succeeds only from `RESOLVED`. Closed investigations cannot be edited or receive new events. Invalid transitions return `409 Conflict`.

## Endpoints

| Method | Path | Behavior |
| --- | --- | --- |
| `POST` | `/api/v1/investigations` | Create a case with an initial `INVESTIGATION_CREATED` timeline event. |
| `GET` | `/api/v1/investigations/{investigation_id}` | Retrieve case fields. |
| `POST` | `/api/v1/investigations/{investigation_id}/events` | Append an analyst, detection, alert, telemetry, behavior-summary, or ML event. |
| `GET` | `/api/v1/investigations/{investigation_id}/timeline` | Retrieve all case events chronologically. |
| `PATCH` | `/api/v1/investigations/{investigation_id}` | Update title/description and/or advance status. |
| `POST` | `/api/v1/investigations/{investigation_id}/close` | Transition a resolved case to `CLOSED`. |

## Requests and responses

Create a case:

```json
{
  "title": "Repeated connection failures",
  "description": "Review activity around the alert.",
  "device_id": "DEVICE-01",
  "sensor_id": "EDGE-01"
}
```

The response includes `investigation_id`, optional device/sensor identifiers, `title`, `description`, `status`, `created_at`, and `updated_at`.

Append an event, including references to existing ROCKS records where relevant:

```json
{
  "timestamp": "2026-09-30T12:04:00Z",
  "event_type": "DETECTION",
  "severity": "HIGH",
  "message": "Suspicious flow detected.",
  "source": "rocks-detection",
  "metadata": {
    "assessment_id": "assessment-123",
    "telemetry_id": "telemetry-456"
  }
}
```

Case timeline entries have this shape:

```json
{
  "event_id": "a generated UUID",
  "investigation_id": "a generated UUID",
  "timestamp": "2026-09-30T12:04:00Z",
  "event_type": "DETECTION",
  "severity": "HIGH",
  "message": "Suspicious flow detected.",
  "source": "rocks-detection",
  "metadata": {
    "assessment_id": "assessment-123",
    "telemetry_id": "telemetry-456"
  }
}
```

Events are append-only and ordered by timestamp, with insertion order retained for equal timestamps. Metadata is limited to JSON values, 8 KiB, and five nesting levels; credential-like keys such as `password`, `api_key`, `token`, `session_secret`, and SMTP keys are rejected. Raw packet payloads are not collected by this API.

Update status with `PATCH /api/v1/investigations/{id}` and `{"status":"IN_PROGRESS"}`. Close a resolved case with `POST /api/v1/investigations/{id}/close`.

## Errors

- `401 Unauthorized`: missing or invalid bearer API key.
- `404 Not Found`: well-formed investigation ID does not exist.
- `409 Conflict`: invalid lifecycle transition or attempt to modify a closed case.
- `422 Unprocessable Entity`: malformed request, invalid ID, unsupported fields, invalid event data, or invalid status value.

## CLI

`rocks investigation create --title ... [--description ...] [--device-id ...] [--sensor-id ...]`, `show <id>`, `timeline <id>`, and `close <id>` operate on the configured local Hub SQLite database. They do not start the Hub or contact a remote service. Closing through the CLI follows the same `RESOLVED`-to-`CLOSED` rule.

The existing device evidence query supports `device_id`, optional `sensor_id`, and timezone-aware `start`/`end` parameters. Its default range is 24 hours, maximum range is 7 days, and results are capped at 1,000 events. It correlates only exact device identifiers, not shared IP addresses.

Investigation provides correlated evidence and context. It does not prove that an attack occurred.
