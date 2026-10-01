# Deployment

This project is designed around a future Linux-first deployment model with both single-machine and distributed configurations.

## All-in-one deployment

The eventual system is intended to support an all-in-one deployment in which:

- ROCKS Edge runs on one Linux machine
- ROCKS Hub runs on the same machine
- the database lives locally
- detection logic runs locally
- the dashboard is served from the same system

This model is useful for small deployments, lab environments, or low-cost monitoring setups. The Command Center is available from the same Hub process at `/dashboard`.

## Distributed deployment

The eventual system is intended to support distributed deployments where:

- multiple Edge sensors are deployed at remote network observation points
- each Edge sensor forwards telemetry to a central self-hosted Hub
- the Hub stores telemetry and runs detection logic
- the Command Center dashboard connects to the Hub for centralized monitoring

This is the intended architecture for larger environments and multiple network segments.

## Chunk 4 Hub communication

The Hub can run on the same Linux machine as Edge at `http://127.0.0.1:8000`, or on a separate self-hosted machine such as `http://ROCKS-HUB-IP:8000`. Edge API keys authenticate telemetry uploads, while the Edge SQLite buffer preserves records when the Hub is unavailable.

## Important constraints

- The project must support managed switch SPAN or port mirroring
- Network observation must not assume that attaching a machine directly to a switch provides every packet
- The system remains metadata-first and does not store payloads
- Detection remains informational and never automatically blocks or attacks devices
- The Hub, API, central SQLite storage, and Edge sender are implemented in Chunk 4; the Command Center is implemented as a read-only Hub-served interface in Chunk 6
- The Command Center is a read-only Hub-served dashboard; configure administrator credentials through environment variables
- Dashboard sessions are separate from Edge API-key authentication
- Synthetic simulator data is local and safe; it does not touch network interfaces
- Alert email is disabled by default and no automatic response is performed
- Configure a managed switch SPAN destination port to deliver selected traffic to Edge
- `rocks edge run --dry-run` validates the local pipeline without root or an interface
- Hub `ONLINE` means recent authenticated telemetry was received within `hub.edge_liveness_timeout_seconds` (default 60); `OFFLINE` means no recent communication was observed, not confirmed physical disconnection
- SQLite files use WAL mode and a 5000 ms busy timeout

## Production safety model

ROCKS is a defensive monitoring, detection, and investigation system. It does not automatically block, isolate, quarantine, disconnect, or change firewall/router policy. Network enforcement is an administrator decision outside ROCKS. Edge capture must use an interface and observation point the institution is authorized to monitor, such as an approved mirror/SPAN or TAP feed.

Telemetry is intended to contain bounded network metadata and behavioral counters, not packet payloads. Hub ingestion rejects oversized bodies/payloads, malformed identifiers and timestamps, non-finite JSON values, credential-like field names, and raw packet-style fields. Detection and ML results are indicators for administrator review, not proof that an attack occurred. Simulator scenarios are synthetic test data and are not real attack evidence.

The setup writer creates configuration files with owner-only (`0600`) permissions. Health and service installation checks reject configuration files readable by group or other users. Production administrators must protect configuration files, backups, service environment files, and any external secret store; use `ROCKS_SESSION_COOKIE_SECURE=true` when serving the dashboard over HTTPS. Normal status/configuration output does not display secret values. Edge API keys are displayed only by the explicit sensor-registration operation so the administrator can provision that sensor.

The administrator dashboard uses its existing signed, HTTP-only session cookie; Edge-to-Hub ingestion uses a registered sensor's bearer API key. Do not place either credential in support logs or screenshots. Dashboard alert projections omit internal SMTP error fields. API write bodies are capped at 128 KiB; Hub telemetry payload JSON is capped at 32 KiB and 32 nested levels, rejects non-finite values, unsupported envelope fields, credential-like keys, and raw packet-style fields. Telemetry queries cap at 1,000 rows; case event and note/action reads cap at 1,000; dashboard edge rows cap at 500. Read filters use bound SQL parameters.

Dashboard/Hub queries are bounded; per-device investigation and case timelines cap returned events, and Edge/dashboard lists have finite row limits. Edge SQLite exposes an explicit `delete_before()` retention operation, but ROCKS does not automatically prune telemetry or case history. Administrators should establish and test an institution-approved retention and backup policy before long-running deployment. No destructive retention migration is performed automatically.

Health checks inspect configuration, local SQLite, endpoint reachability, systemd service state where available, and telemetry freshness. They do not restart services or prove that observed network visibility is complete. Systemd installation and operation occur only through explicit `rocks service` commands; operational hardening does not install or restart services.
