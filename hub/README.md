# ROCKS Hub

ROCKS Hub is the central self-hosted telemetry backend introduced in Chunk 4. It receives structured records from one or more authenticated Edge sensors, validates them against the existing Chunk 3 schema, stores them in a dedicated SQLite database, and exposes small query and health APIs.

## API

- `GET /api/v1/health`
- `POST /api/v1/telemetry`
- `GET /api/v1/telemetry`
- `GET /api/v1/telemetry/{telemetry_id}`
- `GET /api/v1/edges`
- `GET /api/v1/edges/{sensor_id}`
- `GET /api/v1/stats`

Telemetry ingestion uses `Authorization: Bearer <API_KEY>`. Edge API keys are generated during local registration and stored only as salted PBKDF2 hashes. Plaintext keys are displayed only by the registration command and are never returned by API responses.

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

All-in-one:

```text
Linux machine
|- ROCKS Edge
|- ROCKS Hub
|- SQLite
`- future Command Center
```

Distributed:

```text
ROCKS Edge 01 -\|
ROCKS Edge 02 -+--> ROCKS Hub --> future Command Center
ROCKS Edge 03 -/
```

The Command Center, advanced detection, and automatic response are not implemented yet. The Hub is a defensive telemetry backend and does not capture packets, scan networks, block devices, or expose database files over HTTP.

## ML analytics

Chunk 5 adds an optional local ML service behind the Hub. It learns a time-aware baseline from historical `BEHAVIOR_SUMMARY` records, then calculates expected traffic, anomaly score, and storage-retention priority. Telemetry ingestion remains successful when fewer than the configured minimum samples are available or analysis fails. ML does not classify attacks or trigger automatic response.
