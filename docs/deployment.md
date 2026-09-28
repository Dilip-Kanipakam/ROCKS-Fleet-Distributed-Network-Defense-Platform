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
