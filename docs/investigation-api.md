# Device Investigation API

`GET /api/v1/investigations` returns a read-only, chronological event timeline for one device.

## Authentication

Send the existing Hub bearer API key in the `Authorization` header. The key must belong to a registered edge sensor. Requests without a valid key receive `401 Unauthorized`.

## Query parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `device_id` | Yes | Exact device identifier. Related devices are never inferred from a shared IP address. |
| `start` | No | Inclusive ISO 8601 timestamp with timezone. Defaults to 24 hours before `end`. |
| `end` | No | Inclusive ISO 8601 timestamp with timezone. Defaults to the current UTC time. |
| `sensor_id` | No | Restrict results to one sensor identifier. |

The time range must be positive and cannot exceed 7 days. Invalid identifiers, timestamps, or ranges receive `422 Unprocessable Entity`. At most 1,000 events are returned. Timestamps are normalized to UTC in the response.

Example:

```http
GET /api/v1/investigations?device_id=DEVICE-01&start=2026-09-29T12:00:00Z&end=2026-09-30T12:00:00Z&sensor_id=EDGE-01
Authorization: Bearer <registered-edge-api-key>
```

## Response

The response contains `device`, the effective `time_range`, and chronologically ordered `events`. Event types are `TELEMETRY`, `BEHAVIOR_SUMMARY`, `DETECTION`, `ML_ANALYSIS`, `ALERT`, `ALERT_ACKNOWLEDGED`, and `ALERT_RESOLVED`, where corresponding records exist.

Events expose metadata, references, stored detection assessment evidence, and selected ML analysis fields. Raw telemetry payloads, packet contents, credentials, API keys, and notification secrets are not returned. The endpoint only reads SQLite; it does not change alert state, block or disconnect devices, or send email.

Investigation provides correlated evidence and context. It does not prove that an attack occurred.