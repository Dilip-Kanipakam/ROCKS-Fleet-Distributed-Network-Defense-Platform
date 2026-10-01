# ROCKS Command Center

## Overview

The Command Center is the administrator dashboard served by the existing ROCKS Hub process. It is a local operational and investigation view built with FastAPI, Jinja2, CSS, and vanilla JavaScript. No separate frontend server is required.

The dashboard is not a network enforcement console. It does not disconnect, block, quarantine, change firewall/router policy, or send investigation actions to network devices.

## Setup and configuration

Configure a Hub deployment with `rocks setup`, or provide these settings in `config/config.yaml` / environment variables:

- administrator username
- administrator password hash
- dashboard session secret
- dashboard host and port
- `ROCKS_SESSION_COOKIE_SECURE=true` when using HTTPS

Keep the configuration owner-only. Never put real passwords, session secrets, Edge API keys, or SMTP credentials in tracked files.

Check configuration and dashboard state:

```bash
rocks setup --check
rocks dashboard status
```

## Running

Start the Hub and dashboard together:

```bash
rocks dashboard run
```

The default URL is `http://127.0.0.1:8000/dashboard`. `rocks hub run` starts the same FastAPI application without the dashboard-specific command wrapper. Override the bind values with `rocks dashboard run --host <host> --port <port>`.

Login at `/dashboard/login`. Dashboard authentication uses a signed session cookie and is separate from the bearer API keys used by Edge sensors.

State-changing dashboard requests validate same-origin `Origin` or `Referer` headers when supplied. Cross-origin mutations are rejected; read-only GET requests remain available to authenticated sessions.

## Features

- **Fleet overview:** Hub health, Edge online/stale/unknown status, recent telemetry, alerts, investigations, storage, and ML state.
- **Edge and telemetry:** bounded metadata records, event types, sensor filters, and telemetry context.
- **Events and alerts:** deterministic rule titles, reasons, evidence, ML signals, retention priority, severity, simulation markers, and alert lifecycle.
- **Investigation:** device timelines correlate telemetry, detection assessments, ML analysis, alerts, and case events.
- **Cases:** administrators can create cases, advance valid lifecycle states, close resolved cases, and add append-only analyst notes/actions.
- **Notifications:** email state is visible without exposing SMTP configuration. Email is disabled by default.

Investigation evidence is advisory. A detection or alert does not prove an attack.

## Dashboard routes and API

HTML pages:

- `GET /dashboard/login`
- `GET /dashboard`
- `GET /dashboard/edges`
- `GET /dashboard/telemetry`
- `GET /dashboard/telemetry/{telemetry_id}`
- `GET /dashboard/events`
- `GET /dashboard/alerts`
- `GET /dashboard/investigation/{device_id}`

Authenticated JSON routes:

- `GET /api/v1/dashboard/summary`
- `GET /api/v1/dashboard/edges`
- `GET /api/v1/dashboard/telemetry`
- `GET /api/v1/dashboard/telemetry/{telemetry_id}/context`
- `GET /api/v1/dashboard/events`
- `GET /api/v1/dashboard/traffic`
- `GET /api/v1/dashboard/alerts`
- `POST /api/v1/dashboard/alerts/{alert_id}/acknowledge`
- `POST /api/v1/dashboard/alerts/{alert_id}/resolve`
- `POST/PATCH /api/v1/dashboard/investigations` and `/api/v1/dashboard/investigations/{investigation_id}`
- `POST /api/v1/dashboard/investigations/{investigation_id}/close`
- `GET/POST /api/v1/dashboard/investigations/{investigation_id}/notes`
- `GET/POST /api/v1/dashboard/investigations/{investigation_id}/actions`

The corresponding Hub API uses bearer authentication at `/api/v1/investigations/...` for machine-to-machine investigation access.

## Troubleshooting

- **Login returns the login page:** verify the username, password, password hash, and session secret; run `rocks dashboard status`.
- **Dashboard is unavailable:** check `rocks hub status`, the configured host/port, and whether another process owns the port.
- **No Edge rows:** registration alone is not a telemetry check-in. Verify Edge delivery, API key configuration, and the SPAN/TAP observation path.
- **No investigation evidence:** confirm the device ID, sensor filter, and time range; an empty timeline means no matching stored evidence.
- **Storage errors:** run `rocks health verbose` and inspect the configured SQLite path and file permissions.
- **Service startup errors:** use `rocks service status` and `journalctl -u rocks-hub.service`.

Dashboard health describes ROCKS software and stored observations. It does not establish that the monitored network is healthy.
