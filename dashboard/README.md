# ROCKS Command Center

The Command Center is the read-only administrator dashboard served by the existing ROCKS Hub process. It uses FastAPI, Jinja2 templates, CSS, and minimal vanilla JavaScript. No separate frontend server is required.

Routes include `/dashboard/login`, `/dashboard`, `/dashboard/edges`, `/dashboard/telemetry`, `/dashboard/events`, `/dashboard/telemetry/{telemetry_id}`, and the authenticated JSON endpoints under `/api/v1/dashboard/`.

Alert and anomaly-event rows link to their triggering telemetry record. The detail page shows its metadata and bounded related telemetry; recent telemetry rows can open the same view. Dashboard pages and JSON routes require the administrator session, independently of the Hub query API's Edge API-key authentication.

Dashboard access uses a separate signed session cookie and administrator credentials configured through environment variables. It never reuses Edge API keys, exposes credentials, or performs network enforcement.

The interface reports Hub health, Edge status, metadata-only telemetry, ML baseline state, potential anomalies, retention priorities, bounded traffic history, and local investigation alerts. It is strictly read-only and does not block, disconnect, scan, or modify network devices.
