# ROCKS Fleet

**Detect. Analyze. Alert. Restore.**

ROCKS Fleet is a Linux-first, low-cost network security monitoring platform for schools, colleges, small organizations, and lab or hackathon deployments. It observes authorized network metadata, builds local telemetry, detects unusual behavior, and gives administrators evidence for investigation. It is metadata-first: the normal pipeline stores flow and behavior information, not packet payloads.

ROCKS is an observation and decision-support system. It does **not** automatically disconnect, block, quarantine, or isolate users or devices. Any network restriction or recovery action is performed externally by an authorized administrator using the organization’s existing network controls.

## Problem

Small organizations often need useful network visibility without expensive appliances, cloud dependencies, or deep packet storage. ROCKS provides a local-first path from an approved SPAN/TAP observation point to bounded telemetry, explainable rules, optional local ML baselines, alerts, and investigation views.

## Architecture

```text
Network
   |
   v
Authorized SPAN / TAP
   |
   v
ROCKS Edge Sensor
   |
   v
Metadata and flow telemetry
   |
   v
ROCKS Hub
   |
   +--> SQLite storage
   +--> Feature and detection layer
   +--> Risk assessment
   +--> Alert engine
              |
              v
       Dashboard / Investigation
```

### Components

- **Edge Sensor** observes authorized traffic, parses Ethernet/IP/TCP/UDP/ICMP/DNS metadata, tracks flows, calculates features, stores local telemetry, buffers unsent records, and forwards authenticated telemetry to the Hub.
- **ROCKS Hub** authenticates registered Edge sensors, validates telemetry, stores records in SQLite, runs detection and optional ML analysis, creates alerts, and serves the API and dashboard.
- **Feature and detection layer** calculates traffic rate, packet rate, connection activity, unique destinations/ports, DNS and reconnect indicators, and deterministic rule results.
- **Risk assessment** combines rule evidence with the existing ML anomaly and retention signals. These are investigation aids, not attack probabilities or proof of compromise.
- **Alert engine** persists potential anomalies with severity, evidence, and lifecycle state. Email notifications are optional and disabled by default.
- **Dashboard / Investigation** provides authenticated operational summaries, telemetry context, alerts, cases, analyst notes, and actions. Analyst actions are records only; they do not change network state.
- **Administrator** decides whether any external network restriction, remediation, or recovery is appropriate.

## Quick Start

The project requires Python 3.10 or newer. The post-v1.0 development line reports `1.1.0.dev0`; the immutable release remains tagged `v1.0.0`. From the repository root:

```bash
git clone <repository-url>
cd Project-RocksFleet
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Create a runtime configuration with the setup wizard, or copy `config/config.example.yaml` to `config/config.yaml` and fill in the required values. The wizard is preferred because it validates values and writes owner-only configuration permissions:

```bash
rocks setup
rocks setup --check
```

Run safe checks and the test suite:

```bash
rocks --help
rocks edge test
rocks detection test
rocks demo --mode normal
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall src tests
```

## One-command Linux installation

For a simple, non-technical setup on a Linux host, use the repository installer script:

```bash
git clone <repository-url>
cd Project-RocksFleet
./install-rocks.sh
```

The script checks Linux, Python 3.10+, systemd, and sudo; creates or reuses `.venv`; installs ROCKS and its Python dependencies; validates the installed package; then launches the guided configuration wizard. It preserves and validates an existing config unless `--force` is explicitly supplied. After setup, it uses the existing systemd service manager, which grants `CAP_NET_RAW` to the Edge service through the unit rather than running the application as root, enables and starts the configured services, verifies their venv interpreter and service state, runs health checks, and prints `ROCKS READY` plus the dashboard URL. It does not fetch remote installer scripts or modify switches, routers, firewalls, or network topology. Run it as your normal account; sudo is requested only for OS package/service operations.

After installation, use the repository launcher without activating Python:

```bash
./rocks health
./rocks service status
```

For an existing validated config, the CLI can complete service installation without prompting:

```bash
./.venv/bin/rocks install --non-interactive
```

Developers and advanced operators can still create environments manually and run `rocks setup` / `rocks setup --check` directly.

Start the combined Hub and dashboard after configuring a Hub deployment:

```bash
rocks dashboard run
```

The dashboard is served at `http://127.0.0.1:8000/dashboard` by default. Configure administrator credentials before using it. See [dashboard/README.md](dashboard/README.md).

## Installation

`pyproject.toml` is the source of truth for packaging and declares runtime dependencies including FastAPI, Jinja2, PyYAML, Scapy, Uvicorn, joblib, and scikit-learn. The editable install also exposes the `rocks` CLI. The optional `test` dependency provides the HTTP test client; `requirements.txt` contains the complete environment used by this repository.

Linux is the documented target because live packet observation and the optional systemd service workflow are Linux-oriented. Live capture may require appropriate privileges. A normal switch access port does not provide broad visibility; use an authorized managed-switch SPAN/port-mirror session or TAP.

## Configuration

- **`config/config.example.yaml`** documents YAML settings for deployment mode, Edge, Hub, telemetry, health, detection, storage, ML, dashboard, alerts, and email.
- **`.env.example`** lists environment variables for logging, Hub delivery, and optional SMTP notifications.
- Runtime YAML is normally `config/config.yaml`; `ROCKS_CONFIG_PATH` selects another file.
- Edge storage defaults to `data/rocks-edge.db` and `data/rocks-edge-buffer.db`; Hub storage defaults to `data/rocks-hub.db`. Paths can be set under `storage`.
- Hub and dashboard configuration controls bind host/port, dashboard enablement, administrator username/password hash, and signed session secret.
- Registered Edge keys are scoped to their own sensor for Hub reads; configure `ROCKS_ADMIN_API_KEY` for fleet-wide administrative Hub API queries. The dashboard uses its separate signed administrator session.
- Detection thresholds, telemetry windows, Edge buffer limits, liveness, and health freshness are configurable in YAML. Environment overrides exist for selected Edge, Hub, dashboard, detection, and email settings.
- Edge flow tracking is bounded by `edge.max_active_flows` (default 10,000); when full, the oldest inactive flow is evicted deterministically.
- ML is optional and local. It needs historical behavior-summary data before its baseline is useful.

Never commit real passwords, API keys, session secrets, SMTP usernames, SMTP passwords, or other credentials. Keep runtime configuration and `.env` files owner-only. Use `ROCKS_SESSION_COOKIE_SECURE=true` when serving the dashboard over HTTPS.

## Edge Sensor

The Edge path is observation-only. It parses metadata such as addresses, ports, protocols, packet lengths, DNS-related indicators, and timestamps; tracks bounded flows; calculates packet and traffic rates; counts unique destination IPs and ports; identifies devices from observed source identity where possible; creates connection, DNS, and behavior-summary telemetry; and buffers records locally when the Hub is unavailable.

Useful commands:

```bash
rocks edge --help
rocks edge status
rocks edge test
rocks edge telemetry test
rocks edge storage status
rocks edge run --dry-run
rocks edge run --interface <interface> --hub-url <url> --api-key <key> --sensor-id <id>
rocks edge capture --interface <interface>
```

Live capture must be limited to networks and interfaces the operator is authorized to monitor. It does not attack, inject, disconnect, or block traffic.

The Edge key can ingest and query only its own sensor scope. Fleet-wide Hub queries require the configured administrator API key; dashboard users authenticate with the separate signed session.

## Hub and API

Register a sensor and keep the generated API key secret:

```bash
rocks hub edge register --sensor-id ROCKS-EDGE-01
rocks hub edge list
rocks hub run
```

The Hub stores telemetry and exposes these implemented paths:

- `GET /api/v1/health`
- `POST /api/v1/telemetry`
- `GET /api/v1/telemetry`
- `GET /api/v1/telemetry/{telemetry_id}`
- `GET /api/v1/telemetry/context`
- `GET /api/v1/edges`, `GET /api/v1/edges/{sensor_id}`
- `GET /api/v1/stats`
- `GET/POST /api/v1/investigations`
- `GET/PATCH /api/v1/investigations/{investigation_id}`
- `GET /api/v1/investigations/{investigation_id}/timeline`; `POST /api/v1/investigations/{investigation_id}/events`, `/notes`, and `/actions`
- `POST /api/v1/investigations/{investigation_id}/close`

Telemetry ingestion uses the registered Edge bearer API key. Investigation and query responses contain bounded metadata and evidence; they do not enable automatic enforcement.

## Dashboard

The Hub serves the Command Center at `/dashboard`. It requires a separate signed administrator session, not an Edge API key. The dashboard shows fleet and health summaries, Edge freshness, telemetry, detection/ML evidence, alerts, alert lifecycle, investigation timelines, cases, notes, and analyst actions. See [dashboard/README.md](dashboard/README.md).

## Simulator and Demo

The simulator and demo use local synthetic records. They do not send packets, scan networks, require a live interface, or attack external systems. CLI output distinguishes synthetic data from the explicit simulation marker used by simulated deauthentication records. The demo uses a temporary SQLite database and exercises generation, storage, detection, alerts, and investigation without modifying production data:

```bash
rocks demo --mode normal
rocks demo --mode anomaly
rocks demo --mode full
rocks simulate high_traffic --count 5 --sensor-id ROCKS-SIM-01
rocks simulate deauth_related_simulation
```

Synthetic records are not real attack evidence. Scenario-specific deauthentication records are explicitly marked simulation-only; other synthetic scenarios remain synthetic even when their payload does not carry that marker.

## Testing

Run the full suite and the focused integration coverage with the project interpreter:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/test_integration.py
.venv/bin/python -m compileall src tests
```

The 206-test suite covers foundation/setup, Edge parsing and buffering, telemetry, Hub authentication and storage, detection, ML, alerts, dashboard/session behavior, investigations, simulator/demo behavior, and end-to-end integration.

## Security and operational boundaries

ROCKS validates bounded input, authenticates Edge ingestion, uses signed dashboard sessions, avoids packet payload storage in the normal telemetry model, and redacts sensitive operational details. These controls do not replace host, network, or secret-management practices. Detection output is advisory. Administrators must operate the system only at authorized observation points and decide any external restriction or recovery action.

## Deployment

Use `rocks setup` for an Edge, Hub, or all-in-one configuration. A single Linux host can run Hub, dashboard, and an Edge sensor; a distributed deployment can send multiple Edge sensors to one Hub. For persistent Linux operation, the CLI also supports explicit systemd unit generation and service management:

```bash
rocks service generate --output-dir /tmp/rocks-units
rocks service status
```

Installation, permissions, database paths, SPAN/TAP connectivity, and service operation are deployment responsibilities. See [docs/deployment.md](docs/deployment.md).

## Troubleshooting

- **`rocks` is not found:** activate `.venv`, or use `.venv/bin/rocks`.
- **Dependency errors:** recreate the virtual environment and run `pip install -e .`; check that Python is 3.10+.
- **Configuration errors:** run `rocks setup --check`; verify `ROCKS_CONFIG_PATH` and required Hub/dashboard fields.
- **Dashboard login fails:** configure administrator username, password hash, and session secret through setup or environment variables; dashboard sessions are separate from Edge API keys.
- **No telemetry:** check `rocks edge status`, the configured interface, the local buffer, Hub URL/API key, and the authorized SPAN/TAP feed.
- **Capture permission errors:** use the Linux privileges required for passive observation, or start with `rocks edge test` and `rocks edge run --dry-run`.
- **Port already in use:** pass another `--port` to `rocks hub run` or `rocks dashboard run` and keep Hub/dashboard configuration consistent.
- **Tests fail:** run the focused test module first, then `pytest -q`; inspect the first failure and confirm the active interpreter is `.venv/bin/python`.
- **Demo/simulator issues:** use positive bounded counts and supported scenario names from `rocks simulate --help`; these commands do not need live network access.

## Project Status

The current repository includes the Edge observation pipeline, local storage and buffering, authenticated Hub ingestion, scoped Edge/admin Hub authorization, local ML baseline support, explainable detection, alerting, authenticated dashboard investigations, safe demo/simulation workflows, security hardening, and end-to-end tests. Automatic network blocking or disconnection is intentionally outside the project scope.

For development workflow and project structure, see [docs/development.md](docs/development.md). For the data flow, see [docs/architecture.md](docs/architecture.md).
