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

Supported metadata includes Ethernet MAC addresses, IPv4 addresses, protocol, TCP ports and flags, UDP ports, ICMP type, packet length, and DNS-related indicators. Complete packet payloads are never stored or logged.

Each flow tracks first and last observation time, packet count, bytes, duration, packet rate, and byte rate. Feature records include traffic volume and rate, protocol counts, active flows, unique destinations and sources, connection counts, and an optional IP/MAC-based device identifier. Device identifiers describe observed network endpoints only; ROCKS does not identify human users.

## Live capture and SPAN

Live capture requires an authorized account with the operating-system privileges needed by Scapy and a valid interface, for example:

```bash
rocks edge capture --interface eth0
```

The capture abstraction validates the interface, invokes a callback with packets, uses `store=False`, and supports graceful stop requests. It does not modify interfaces, firewall rules, or traffic.

For visibility into traffic from other devices or network segments, the sensor should receive traffic through a managed-switch SPAN or port-mirroring configuration. Connecting a sensor to an ordinary switch access port does **not** automatically expose all network traffic.

Deploy and operate Edge only on networks and systems where monitoring is authorized. ROCKS is passive and metadata-first: it does not scan, attack, block, or disconnect devices.

## Planned later chunks

Telemetry transmission, local database storage, ROCKS Hub, ML, anomaly and retention scoring, and the Command Center dashboard are not implemented in Chunk 2.
