# ROCKS Command Center

The Command Center is served by the existing ROCKS Hub process. Evidence views are read-only; a small administrator workflow can create and advance investigation cases. It uses FastAPI, Jinja2 templates, CSS, and minimal vanilla JavaScript. No separate frontend server is required.

Routes include `/dashboard/login`, `/dashboard`, `/dashboard/edges`, `/dashboard/telemetry`, `/dashboard/events`, `/dashboard/telemetry/{telemetry_id}`, `/dashboard/investigation/{device_id}`, and the authenticated JSON endpoints under `/api/v1/dashboard/`.

Alert and anomaly-event rows link to their triggering telemetry record. The detail page shows its metadata and bounded related telemetry; recent telemetry rows can open the same view. Dashboard pages and JSON routes require the administrator session, independently of the Hub query API's Edge API-key authentication.

Dashboard access uses a separate signed session cookie and administrator credentials configured through environment variables. It never reuses Edge API keys, exposes credentials, or performs network enforcement.

The interface reports Hub health, Edge status, metadata-only telemetry, ML baseline state, potential anomalies, retention priorities, bounded traffic history, and local investigation alerts. Administrators can acknowledge or resolve an alert from the alert list once they have inspected the related telemetry. Valid lifecycle transitions are `OPEN -> ACKNOWLEDGED`, `OPEN -> RESOLVED`, and `ACKNOWLEDGED -> RESOLVED`. `RESOLVED -> ACKNOWLEDGED` and `RESOLVED -> OPEN` are rejected, and alert resolution does not imply a confirmed attack.

The events and alert tables include deterministic rule titles, reasons, metric evidence, existing ML anomaly signal, and an explicit `SIMULATED` marker for simulator-only deauthentication examples. Reconnaissance-like or DNS-related evidence is a prompt for investigation, not proof of a scan, attack, malware, or tunneling.

The alert list displays notification state (`Sent`, `Failed`, `Not sent`, or `Not configured`) without SMTP settings or credentials. Email is disabled by default and is not required for alert creation or investigation.

## Device Investigation and Cases

Use **Investigate Device** beside an alert with a device identifier to open `/dashboard/investigation/{device_id}` centered on the alert timestamp. The page uses the exact device identifier, optional sensor filter, and bounded start/end values to show the Hub's chronological metadata-first timeline. It displays only stored telemetry metadata, detection assessment evidence, ML analysis, and alert state; packet payloads and credentials are not rendered. An empty result means no matching evidence was available for that device and range. Invalid ranges and temporary storage/API errors are shown as administrator-facing messages without stack traces.

Dashboard pages and their case action endpoints require the existing signed administrator session. Browser requests use same-origin session authentication; they do not expose or reuse Edge API keys. Alert navigation is read-only: opening an investigation does not create, acknowledge, or resolve an alert, send email, or change network state. Existing alert lifecycle controls remain unchanged.

From a device investigation page, an administrator can create a case, inspect its timeline and status, move `OPEN` to `IN_PROGRESS`, move `IN_PROGRESS` to `RESOLVED`, then close a resolved case. The interface presents only the action valid for the current state. The Hub remains authoritative; if it rejects a transition, the page displays the returned error. Closed cases cannot be modified. No block, disconnect, quarantine, router, or firewall controls are present.

For an open case, the investigation page also provides append-only analyst notes and a controlled action-category form. Notes display newest first and appear in the chronological case timeline as `ANALYST_NOTE`; action records appear as `ANALYST_ACTION`. Categories are `OBSERVED`, `INVESTIGATING`, `DEVICE_REVIEWED`, `TRAFFIC_REVIEWED`, `ADMIN_ACTION_REQUIRED`, and `RESOLVED`. The `RESOLVED` action category records a note only and does not change case lifecycle state. The dashboard uses the signed-in administrator username as the note/action author. Closed cases show existing notes but do not offer note or action forms.

Analyst actions are records only: they do not automatically enforce network controls, change alert state, send investigation email, or perform firewall/router operations. Investigation notes are limited to 2,000 characters; credential-like values and structured payload-style content are rejected. Notes/actions cannot be edited or deleted.

Simulator-derived deauthentication events are labeled **SIMULATION ONLY** and are not presented as observed Wi-Fi activity. Rule names and explanations retain careful terms such as “Reconnaissance-like behavior”; evidence is not presented as a confirmed attack.

Investigation provides correlated evidence and context. It does not prove that an attack occurred.

For host-level operations, use `rocks health` or `rocks health verbose` for service state, Hub/dashboard reachability, read-only SQLite checks, Edge buffer availability, and telemetry freshness. Service status is not equivalent to telemetry flow. Troubleshoot systemd failures with `rocks service status` and `journalctl -u rocks-hub.service`; stale telemetry may require checking Edge delivery and the authorized SPAN/TAP observation path. These diagnostics do not change services or network configuration, and a healthy ROCKS installation does not assert that the monitored network is healthy.

Authenticated note and action APIs are available under `/api/v1/dashboard/investigations/{investigation_id}/notes` and `/api/v1/dashboard/investigations/{investigation_id}/actions`; the corresponding Hub API uses `/api/v1/investigations/{investigation_id}/notes` and `/actions` with the existing bearer-key authentication.

## Fleet Overview

The main Command Center summarizes registered, online, stale, and unknown Edge sensors; telemetry received in the last five minutes; open and high/critical active alerts; open investigations; and ML baseline state. Counts come from Hub SQLite records. Recent alert entries show stored severity, rule name when available, device, timestamp, and status. An alert with a device identifier links to the existing device investigation view using that alert's timestamp and sensor.

Edge `ONLINE` means the Hub has seen the sensor within the configured Edge liveness timeout. `STALE` means it has been seen but is now outside that timeout. `UNKNOWN` means it has never checked in. The table separately shows the last Hub telemetry timestamp and stored telemetry count; registration alone does not imply online status.

The system health section uses the existing read-only `rocks health` checks and displays their aggregate and component states without diagnostic detail fields or configuration values. It is evaluated when the dashboard page loads; dashboard data refreshes every 30 seconds using authenticated read-only endpoints. Empty sensor, alert, and telemetry collections are reported explicitly; unavailable fleet data uses a generic error message.

The Command Center is an operational summary, not a network enforcement console. Hub health and Edge freshness describe software connectivity and stored observations; they do not establish network health, attack confirmation, or prevention effectiveness. An unavailable per-Edge Hub connection signal is not inferred from registration.
