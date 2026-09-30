# ROCKS Command Center

The Command Center is the read-only administrator dashboard served by the existing ROCKS Hub process. It uses FastAPI, Jinja2 templates, CSS, and minimal vanilla JavaScript. No separate frontend server is required.

Routes include `/dashboard/login`, `/dashboard`, `/dashboard/edges`, `/dashboard/telemetry`, `/dashboard/events`, `/dashboard/telemetry/{telemetry_id}`, and the authenticated JSON endpoints under `/api/v1/dashboard/`.

Alert and anomaly-event rows link to their triggering telemetry record. The detail page shows its metadata and bounded related telemetry; recent telemetry rows can open the same view. Dashboard pages and JSON routes require the administrator session, independently of the Hub query API's Edge API-key authentication.

Dashboard access uses a separate signed session cookie and administrator credentials configured through environment variables. It never reuses Edge API keys, exposes credentials, or performs network enforcement.

The interface reports Hub health, Edge status, metadata-only telemetry, ML baseline state, potential anomalies, retention priorities, bounded traffic history, and local investigation alerts. Administrators can acknowledge or resolve an alert from the alert list once they have inspected the related telemetry. Valid lifecycle transitions are `OPEN -> ACKNOWLEDGED`, `OPEN -> RESOLVED`, and `ACKNOWLEDGED -> RESOLVED`. `RESOLVED -> ACKNOWLEDGED` and `RESOLVED -> OPEN` are rejected, and alert resolution does not imply a confirmed attack.

The events and alert tables include deterministic rule titles, reasons, metric evidence, existing ML anomaly signal, and an explicit `SIMULATED` marker for simulator-only deauthentication examples. Reconnaissance-like or DNS-related evidence is a prompt for investigation, not proof of a scan, attack, malware, or tunneling.

The alert list displays notification state (`Sent`, `Failed`, `Not sent`, or `Not configured`) without SMTP settings or credentials. Email is disabled by default and is not required for alert creation or investigation.

For host-level operations, use `rocks health` or `rocks health verbose` for service state, Hub/dashboard reachability, read-only SQLite checks, Edge buffer availability, and telemetry freshness. Service status is not equivalent to telemetry flow. Troubleshoot systemd failures with `rocks service status` and `journalctl -u rocks-hub.service`; stale telemetry may require checking Edge delivery and the authorized SPAN/TAP observation path. These diagnostics do not change services or network configuration, and a healthy ROCKS installation does not assert that the monitored network is healthy.
