# ROCKS Fleet Architecture

ROCKS Fleet is a local-first monitoring and investigation platform. The implementation is a Python package with a FastAPI Hub, SQLite storage, an optional live Edge agent, deterministic detection, optional local ML, and a Hub-served dashboard.

## High-level architecture

```text
Authorized network observation point
          |
          v
      Edge Sensor
          |
          v
 Metadata, flows, features
          |
          v
      Telemetry
          |
          v
        Hub API
       /   |    \
      v    v     v
  SQLite Detection Alerts
             |       |
             +-------+
                 |
                 v
       Dashboard / Investigation
```

The Edge observes. The Hub processes and stores. The dashboard presents evidence. An administrator, outside ROCKS, decides whether to apply any network restriction or recovery action.

## Edge data flow

1. `PacketCapture` receives packets from an authorized interface, normally fed by a managed-switch SPAN/port mirror or TAP.
2. `parse_packet` extracts bounded Ethernet/IP/TCP/UDP/ICMP/DNS metadata rather than packet payloads.
3. `FlowTracker` maintains bounded five-tuple flow state and emits connection records when flows expire or are flushed.
4. `FeatureAggregator` calculates windowed packet count, byte counts, traffic rate, packet rate, active flows, unique destinations/ports, and related counters.
5. Telemetry constructors create versioned `CONNECTION`, `DNS`, `RECONNECT`, or `BEHAVIOR_SUMMARY` records.
6. `TelemetryStorage` and `TelemetryBuffer` provide local persistence and offline delivery. Records are removed from the send buffer only after Hub acknowledgement.

The Edge may run without a Hub for local buffering. `--dry-run` and the synthetic Edge test do not capture live traffic.

## Hub processing flow

```text
POST /api/v1/telemetry
          |
          v
Bearer API-key authentication
          |
          v
Schema, identifier, timestamp, payload validation
          |
          v
SQLite insert and Edge liveness update
          |
          +--> deterministic DetectionEngine
          +--> optional MLService analysis
          +--> AlertEngine and optional email notification
          |
          v
Queries, investigations, dashboard projections
```

The Hub registers sensors with hashed API keys, validates incoming telemetry, prevents duplicate record insertion, stores records in indexed SQLite tables, and exposes health, Edge, telemetry, statistics, and investigation APIs.

## Detection and assessment

`DetectionEngine` evaluates behavior-summary, DNS, reconnect, and explicitly evidenced deauthentication-related metadata against configured thresholds. Results include triggered rule IDs, severity, reasons, counters, thresholds, and simulation state. The existing `MLService` can add a time-aware baseline anomaly score and retention priority when enabled and trained.

The assessment is not an attack classifier. Terms such as “reconnaissance-like” describe metadata patterns and require administrator review. No detection path changes network state.

## Alert flow

`AlertEngine` creates a stable alert for a triggered rule or configured ML signal. `HubStorage` persists the alert with telemetry ID, sensor, device, timestamp, severity, evidence, and lifecycle fields. The dashboard can acknowledge or resolve alerts. Optional email notification is bounded and disabled by default; an SMTP failure does not prevent alert storage.

## Investigation flow

Investigation views correlate:

- stored telemetry metadata
- detection assessments
- ML analysis records
- alert state and lifecycle events
- investigation cases and case events
- append-only analyst notes and actions

The Hub exposes `/api/v1/investigations/...`; the dashboard exposes the corresponding authenticated `/api/v1/dashboard/investigations/...` routes. Case state changes and analyst records are persisted in SQLite. They do not invoke firewall, router, isolation, or device-control operations.

## Dashboard flow

The dashboard is mounted in the Hub process. Browser pages and JSON projections require a signed administrator session. The dashboard service reads bounded Hub storage projections for fleet summary, Edge status, telemetry, events, alerts, health, traffic, and investigations. Edge API keys are never reused as dashboard credentials.

## Storage boundaries

Edge SQLite stores local telemetry and its delivery buffer. Hub SQLite stores registered sensors, telemetry, ML analysis, detection assessments, alerts, investigations, and investigation events. SQLite WAL mode and bounded queries support the local-first deployment model. Retention and backups remain deployment responsibilities.

## Safety boundary

ROCKS is designed for authorized defensive monitoring. It does not send attack traffic, inject packets, automatically block or disconnect devices, or claim that a healthy ROCKS process proves network health. Synthetic demo scenarios use temporary local storage and do not touch real interfaces.
