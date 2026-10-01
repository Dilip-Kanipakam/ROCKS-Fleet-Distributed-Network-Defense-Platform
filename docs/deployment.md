# Deployment

This document separates reproducible development/demo use from deployment considerations. ROCKS is Linux-first; live capture and the optional systemd workflow depend on operating-system permissions and an authorized observation point.

## Local development and demo

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
rocks setup --check
rocks edge test
rocks demo --mode full
.venv/bin/python -m pytest -q
```

The demo and simulator are synthetic-only. They do not require an interface, send packets, or modify production databases. The Edge test is also non-root and synthetic.

## All-in-one deployment

A single Linux host can run an Edge sensor, Hub, SQLite databases, and the dashboard. Run `rocks setup` and select **Edge + Hub**. Configure:

- a sensor ID and authorized capture interface
- Hub bind host/port and Hub SQLite path
- dashboard administrator username/password and session secret
- Edge-to-Hub registration key
- telemetry window, send interval, and buffer limit

Start the combined process with:

```bash
rocks dashboard run
```

The default dashboard URL is `http://127.0.0.1:8000/dashboard`. Bind to a controlled address and protect the connection with the surrounding host/network controls when exposing it beyond localhost.

## Distributed deployment

For multiple observation points:

1. Run the Hub and dashboard on a central Linux host.
2. Register each sensor with `rocks hub edge register --sensor-id <id>`.
3. Store each generated API key securely on its corresponding Edge host.
4. Configure each Edge with the Hub URL, API key, sensor ID, interface, and send interval.
5. Confirm delivery with `rocks edge status`, `rocks hub edge list`, `rocks hub status`, and dashboard telemetry.

The Hub must be reachable from each Edge over the configured URL. The Edge buffer retains records during temporary Hub outages, subject to its configured capacity.

## Observation point and permissions

An ordinary switch access port does not expose all campus or organizational traffic. Use an institution-approved managed-switch SPAN/port-mirror destination or TAP. Capture only networks and interfaces the operator is authorized to monitor.

Live packet observation may require Linux capabilities or administrator privileges. Start with `rocks edge test`, `rocks edge run --dry-run`, and `rocks edge status` to validate software without live capture. ROCKS does not configure the switch, SPAN session, TAP, router, firewall, or network topology.

## Configuration and database

Runtime configuration is normally `config/config.yaml`; `config/config.example.yaml` is a template. `ROCKS_CONFIG_PATH` selects another YAML file. Database paths are configured under `storage` and default to:

- `data/rocks-edge.db`
- `data/rocks-edge-buffer.db`
- `data/rocks-hub.db`

Protect configuration, `.env`, database backups, and generated service files. Do not commit passwords, API keys, dashboard session secrets, or SMTP credentials. Use `ROCKS_SESSION_COOKIE_SECURE=true` when the dashboard is served over HTTPS.

## Linux services

Service management is explicit and optional. Generate units for review without installing them:

```bash
rocks service generate --output-dir /tmp/rocks-units
rocks service status
```

Installation and start/stop operations require administrator approval and systemd availability:

```bash
sudo rocks service install
rocks service status
journalctl -u rocks-hub.service -f
journalctl -u rocks-edge.service -f
```

The service manager does not configure network visibility or copy credentials into unit files. Review the generated units and local configuration before installation.

## Prototype, development, and deployment boundaries

- **Prototype/demo:** use synthetic commands and temporary demo storage; no live interface is needed.
- **Development:** use the virtual environment, local SQLite, focused tests, and `--dry-run` checks.
- **Deployment:** add authorized SPAN/TAP connectivity, secret management, protected host access, backups, retention policy, monitoring, and a tested service procedure.

The repository provides a monitoring and investigation platform. It does not claim automatic enforcement, complete network visibility, measured attack-classification accuracy, or unattended production remediation.

## Operational checks

```bash
rocks health
rocks health verbose
rocks hub status
rocks dashboard status
rocks edge status
```

These checks report ROCKS software state, storage liveness, configured endpoints, and telemetry freshness. A healthy result does not prove that the monitored network is healthy or that the observation point sees every desired segment.
