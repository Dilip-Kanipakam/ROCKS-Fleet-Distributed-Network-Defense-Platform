# ROCKS Edge

ROCKS Edge is the network observation layer of ROCKS Fleet. The implementation lives under `src/rocks/edge/`; this top-level directory contains deployment documentation.

## Current Chunk 2 capabilities

The first Edge pipeline is now implemented for authorized defensive monitoring:

1. Scapy packet capture abstraction
2. Metadata-only protocol parsing
3. Five-tuple flow tracking
4. Configurable flow expiration
5. In-memory time-window feature extraction
6. A non-root synthetic demonstration through `rocks edge test`
7. Versioned structured telemetry records
8. SQLite local telemetry storage
9. A persistent local offline buffer

Supported metadata includes Ethernet MAC addresses, IPv4 addresses, protocol, TCP ports and flags, UDP ports, ICMP type, packet length, and DNS-related indicators. Complete packet payloads are never stored or logged.

Each flow tracks first and last observation time, packet count, bytes, duration, packet rate, and byte rate. Feature records include traffic volume and rate, protocol counts, active flows, unique destinations and sources, connection counts, and an optional IP/MAC-based device identifier. Device identifiers describe observed network endpoints only; ROCKS does not identify human users.

## Chunk 3 telemetry and storage

Edge telemetry uses schema version `1.0` and a common envelope containing `timestamp`, `sensor_id`, `device_id`, and `event_type`. Supported events are `CONNECTION`, `DNS`, `RECONNECT`, and `BEHAVIOR_SUMMARY`. Timestamps are UTC ISO-8601 values. Records contain metadata and behavioral counters only, plus optional future retention fields that are currently null.

Behavior summaries use a configurable 60-second window by default. The current Edge stores telemetry locally in SQLite with indexed timestamp, sensor, device, and event fields. A separate SQLite-backed FIFO buffer keeps records available across process restarts when future Hub delivery is unavailable.

The Edge stores telemetry locally and forwards buffered records to the ROCKS Hub when configured and available.

## Live capture and SPAN

Live capture requires an authorized account with the operating-system privileges needed by Scapy and a valid interface, for example:

```bash
rocks edge capture --interface eth0
```

The capture abstraction validates the interface, invokes a callback with packets, uses `store=False`, and supports graceful stop requests. It does not modify interfaces, firewall rules, or traffic.

For visibility into traffic from other devices or network segments, the sensor should receive traffic through a managed-switch SPAN or port-mirroring configuration. Connecting a sensor to an ordinary switch access port does **not** automatically expose all network traffic.

Deploy and operate Edge only on networks and systems where monitoring is authorized. ROCKS is passive and metadata-first: it does not scan, attack, block, or disconnect devices.

## Live Edge agent

For first-time configuration, run `rocks setup` and choose **Edge Sensor**. Setup lists interfaces present on this machine and validates the selected interface, sensor ID, Hub URL, API key, and send interval. For a distributed deployment, register the sensor on the Hub first with `rocks hub edge register --sensor-id ROCKS-EDGE-01`; provide the one-time displayed key to Edge setup. The key is stored in the owner-only local YAML config and is not shown in the completion summary. Setup does not change interface flags or network hardware.

An available interface is only the local capture device. Broad visibility requires connecting it to a SPAN/port-mirror destination or an appropriate TAP; a normal switch access port does not reveal all campus traffic.

Live telemetry uses the existing schema 1.0 builders. `BEHAVIOR_SUMMARY` is emitted per observed source IP; `bytes_sent` counts traffic from that source toward destinations and `bytes_received` counts traffic toward that source. DNS queries to destination port 53 are grouped by source/destination endpoint and transport within each flush window; failure count remains 0 because current metadata does not establish DNS response failures. Expired idle flows produce `CONNECTION` records with directional sent bytes and unknown received bytes. `RECONNECT` is not emitted: this passive packet metadata does not reliably distinguish reconnection from retries or ordinary connection behavior. No event type confirms an attack.

Each flush persists and buffers the generated `BEHAVIOR_SUMMARY` and aggregated DNS events. A flow that expires after the existing idle timeout is emitted once as a `CONNECTION` event; periodic flush checks expiration even during quiet periods. The current parser does not provide reliable connection-failure evidence, so reconnect and failure counters are not fabricated.

The operational agent connects the existing capture, parser, flow, feature, telemetry, local SQLite, persistent buffer, and Hub sender components:

```text
Interface -> metadata parser -> flows/features -> telemetry -> local storage/buffer -> Hub
```

Start it with:

```bash
rocks edge run --interface eth0 --hub-url http://127.0.0.1:8000 --api-key '<edge-api-key>' --sensor-id ROCKS-EDGE-01
```

The API key is never printed or included in status output. When the Hub is unavailable, telemetry remains in the local SQLite buffer. Records are removed only after successful Hub acknowledgement. Stop with `Ctrl+C`; the agent stops capture and flushes safe local state.

The Edge telemetry database and persistent buffer use SQLite WAL mode with a 5-second busy timeout to tolerate short concurrent read/write contention. Hub `ONLINE`/`OFFLINE` status reflects recent successful communication, not guaranteed physical connectivity.

For a non-root demonstration without a physical interface:

```bash
rocks edge run --dry-run
```

The Edge requires a managed-switch SPAN or port-mirroring setup for visibility into selected ports or VLANs. Connecting a laptop to an ordinary switch port does not automatically expose all network traffic.

All records are persisted locally and added to the persistent buffer before Hub delivery. The sender removes them only after successful acknowledgement.
