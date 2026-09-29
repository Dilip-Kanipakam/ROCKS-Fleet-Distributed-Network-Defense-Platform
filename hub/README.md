# ROCKS Hub

ROCKS Hub is the central self-hosted telemetry backend introduced in Chunk 4. It receives structured records from one or more authenticated Edge sensors, validates them against the existing Chunk 3 schema, stores them in a dedicated SQLite database, and exposes small query and health APIs.

## API

- `GET /api/v1/health`
- `POST /api/v1/telemetry`
- `GET /api/v1/telemetry`
- `GET /api/v1/telemetry/context`
- `GET /api/v1/telemetry/{telemetry_id}`
- `GET /api/v1/edges`
- `GET /api/v1/edges/{sensor_id}`
- `GET /api/v1/stats`

Only `GET /api/v1/health` is public. Telemetry ingestion and query endpoints (`GET /api/v1/telemetry`, `GET /api/v1/telemetry/context`, `GET /api/v1/telemetry/{telemetry_id}`, `GET /api/v1/edges`, `GET /api/v1/edges/{sensor_id}`, and `GET /api/v1/stats`) require `Authorization: Bearer <registered-edge-api-key>`.

The bounded metadata-only context query accepts `telemetry_id` or an identity filter (`device_id` or `source_ip`), with optional `sensor_id`, `event_type`, `since`, and `until` filters. It returns the triggering record when anchored by `telemetry_id` plus up to 100 newest matching records; its default limit is 50. It does not return packet payloads or credentials.

Alerts carry the same metadata-only approach. Each alert records a `telemetry_id` and a lifecycle state in SQLite. The default state is `OPEN`; an administrator may move it to `ACKNOWLEDGED` and then `RESOLVED`. These transitions are validated, and a resolved alert remains an operational state value rather than a claim that an attack was confirmed.

Optional email notifications are disabled by default. When enabled, only newly inserted alerts at or above `email.minimum_severity` are considered (`HIGH` by default; `WARNING` includes both current severities). SQLite records one claimed attempt per alert with state, attempt count, sent timestamp, and a safe error code. Duplicate telemetry/alert processing, dashboard views, acknowledgement, and resolution do not cause another send. SMTP failures do not change alert lifecycle or interrupt ingestion.

Edge API keys are generated during local registration and stored only as salted PBKDF2 hashes. Plaintext keys are displayed only by the registration command and are never returned by API responses. Authentication failures use a generic `401 Invalid credentials` response.

Hub SQLite connections use WAL mode for file-backed databases and a 5-second busy timeout. Edge liveness is derived from successful authenticated telemetry communication (`last_seen`). The configurable `hub.edge_liveness_timeout_seconds` defaults to 60 seconds. `ONLINE` means the Hub observed communication within that window; `OFFLINE` means no recent communication was observed, not that the physical sensor is definitely disconnected. The last-seen time is retained for offline sensors.

Start the Hub locally with:

```bash
rocks hub run --host 127.0.0.1 --port 8000
```

Register an Edge sensor locally:

```bash
rocks hub edge register --sensor-id ROCKS-EDGE-01
```

The Hub has its own SQLite database and does not reuse an Edge database. Duplicate telemetry IDs are acknowledged without creating a second record. The Edge sender removes a buffered record only after a successful Hub response; failures leave local telemetry available.

## Deployment

For a new Hub / Command Center host, run `rocks setup` and select **Hub / Command Center**. The wizard configures the SQLite path and dashboard credentials, hashes the password, generates a random session secret when needed, and writes `config/config.yaml` with owner-only permissions. Dashboard settings are loaded from that file unless their corresponding existing environment variables override them. Register each remote Edge on the Hub with `rocks hub edge register --sensor-id <sensor-id>` and transfer the displayed API key securely; the Hub retains only its salted hash.

For a single-machine installation, select **Edge + Hub**. The wizard registers the local Edge identity in the configured Hub database and writes the generated API key only to the protected local config. It does not print the key.

The wizard configures software only. It does not configure a managed switch, SPAN session, TAP, router, firewall, or network topology. The Edge capture interface must be connected to an appropriate observation point for traffic visibility.

For continuous operation, `rocks service install` installs `rocks-hub.service` for Hub mode, or both `rocks-edge.service` and `rocks-hub.service` for all-in-one mode. The Hub unit starts `rocks dashboard run`, which serves the Hub APIs and mounts the dashboard in that same process; do not start a separate dashboard service. Installation/removal are explicit system administrator actions. Check state with `rocks service status`, follow logs with `journalctl -u rocks-hub.service -f`, and remove the units with `sudo rocks service uninstall`.

All-in-one:

```text
Linux machine
|- ROCKS Edge
|- ROCKS Hub
|- SQLite
`- future Command Center
`- Command Center
```

Distributed:

```text
ROCKS Edge 01 -\|
ROCKS Edge 02 -+--> ROCKS Hub --> Command Center
ROCKS Edge 03 -/
```

Advanced detection and automatic response are not implemented yet. The Hub is a defensive telemetry backend and does not capture packets, scan networks, block devices, or expose database files over HTTP.

Configure SMTP in the local `email` YAML section or use the `ROCKS_SMTP_*` environment overrides, especially `ROCKS_SMTP_PASSWORD` for secrets. STARTTLS with certificate verification is enabled by default; SMTP connection timeout defaults to five seconds and is capped at 30 seconds. Run `rocks alerts email-test` explicitly to test delivery without making a fake alert. It prints status/reason codes only. If delivery fails, the `OPEN` alert remains available and the Hub continues processing; examine `notification_error` in alert state and the Hub journal for diagnosis.

## ML analytics

Chunk 5 adds an optional local ML service behind the Hub. It learns a time-aware baseline from historical `BEHAVIOR_SUMMARY` records, then calculates expected traffic, anomaly score, and storage-retention priority. Telemetry ingestion remains successful when fewer than the configured minimum samples are available or analysis fails. ML does not classify attacks or trigger automatic response.
