# ROCKS Fleet

ROCKS Fleet is a low-cost, distributed, self-hosted network security monitoring platform designed for Linux-based deployments. The project is intentionally metadata-first: it focuses on observing network metadata and flow features rather than storing packet payloads.

## Architecture overview

The planned architecture is:

Network
  ↓
Managed Switch SPAN / Port Mirroring
  ↓
ROCKS Edge
  ↓
Network metadata / flow features
  ↓
Structured telemetry
  ↓
ROCKS Hub
  ↓
Storage + Detection + ML
  ↓
Command Center / Dashboard

## ROCKS Edge

ROCKS Edge is the observation layer responsible for reading authorized mirrored traffic, extracting metadata and flow features, buffering local data, and forwarding structured telemetry to the Hub.

## ROCKS Hub

ROCKS Hub is the centralized collection and analysis layer. It receives authenticated telemetry, stores it, runs the local ML baseline, and serves the API and Command Center dashboard.

## Command Center

The Command Center is the read-only administrator dashboard for investigation, monitoring, and operational awareness. It is served by the existing Hub process at `/dashboard`.

## Metadata-first approach

ROCKS is designed around metadata and flow features instead of packet payload storage. This keeps the system more privacy-conscious, reduces storage overhead, and better matches the project's low-cost, self-hosted monitoring goals.

## Future ML purpose

Machine learning is planned for a later chunk and will be used to:

- learn time-dependent network traffic baselines
- detect unusual traffic spikes
- generate anomaly scores
- help prioritize telemetry retention to reduce storage use

ML is local and baseline-oriented. It does not prove that an attack occurred.

## Current development status

This repository currently contains the ROCKS Fleet foundation and first Edge observation pipeline:

- project structure
- Python package metadata
- configurable CLI
- configuration and logging scaffolding
- Scapy-based Edge packet metadata parsing
- bounded five-tuple flow tracking and expiration
- in-memory time-window traffic features
- non-root synthetic Edge pipeline demonstration
- versioned telemetry records with connection, DNS, reconnect, and behavior-summary events
- SQLite local telemetry storage and a persistent offline buffer
- central ROCKS Hub ingestion API with authenticated Edge registration
- local Hub-side time-aware baseline learning and retention prioritization
- safe synthetic simulator and local investigation alerts
- documentation and test baseline

Chunks 1 through 6 provide the Edge, telemetry, Hub, ML, and read-only Command Center layers. Chunk 7 integrates safe synthetic scenarios, local investigation alerts, and an end-to-end MVP demonstration. Automatic response remains intentionally unimplemented.

## Quick Demo

The simulator generates telemetry only; it never sends packets, scans networks, or performs attacks.

```bash
rocks demo
```

The demo creates 20 historical baseline records in a temporary SQLite database, trains the local model, compares normal traffic with a synthetic high-traffic spike, and creates a HIGH investigation alert. ML needs historical baseline data before it becomes ready. An anomaly indicates behavior that differs from the learned baseline; it does not prove an attack.

Optional scenario generation is available with `rocks simulate normal`, `rocks simulate anomaly`, and `rocks simulate mixed`. Dashboard alerts are investigation-only. Optional email notifications are disabled by default; ROCKS continues storing alerts if SMTP is unavailable.

## Live Edge

Run the operational Edge agent with `rocks edge run --interface <interface> --hub-url <url> --api-key <key> --sensor-id <id>`. Use `rocks edge run --dry-run` for a safe local check. A managed switch must be configured to mirror selected ports or VLAN traffic to the Edge through a SPAN destination port; an ordinary switch connection does not expose all traffic.

## Setup wizard

Install from the repository root, then start the interactive setup:

```bash
git clone <repository-url>
cd Project-RocksFleet
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
rocks setup
```

Choose one of the prompted deployment modes:

- **Edge Sensor** configures a stable sensor ID, an available interface, the Hub URL, an Edge API key, and its send interval. On the Hub, first register the sensor with `rocks hub edge register --sensor-id ROCKS-EDGE-01`; the generated key is shown once and must be entered into the Edge setup.
- **Hub / Command Center** configures the Hub, SQLite database path, and dashboard administrator. The password is entered without echo, hashed with the existing password hasher, and never included in the setup summary. The session secret is generated cryptographically when one is not already configured.
- **Edge + Hub** configures both on one machine and registers the Edge identity in the local Hub database, storing only its hashed key there.

The generated `config/config.yaml` is the runtime YAML configuration; it is ignored by Git and written with owner-only permissions. `ROCKS_CONFIG_PATH` can select another YAML path, and existing environment-variable overrides continue to take precedence. A non-interactive invocation must provide `--mode` and all required settings; `--force` is required to update an existing config without an interactive confirmation. Validate an existing configuration without writing it with `rocks setup --check`.

After setup, validate the software configuration and synthetic Edge pipeline:

```bash
rocks setup --check
rocks test
rocks edge test
rocks hub status
rocks dashboard status
```

For broad network visibility, connect the selected Edge interface to an appropriate managed-switch SPAN/port-mirroring session or a TAP. Connecting a normal switch access port does not expose all campus traffic. ROCKS setup configures software only; it does not configure the physical switch, SPAN session, TAP, router, firewall, or network topology.

Start the Hub/Command Center with `rocks dashboard run` (or `rocks hub run`). Start an Edge sensor with `rocks edge run`. Edge capture may require the operating-system privileges needed for packet observation.

## Linux Services

For continuous operation on a Linux host with systemd, complete setup and software checks first. Service installation is separate from `rocks setup` and explicitly requires administrator approval:

```bash
rocks setup
rocks test
rocks service install
rocks service status
```

`rocks service install` installs and starts only the units required by the configured mode. Edge mode installs `rocks-edge.service`; Hub mode installs `rocks-hub.service`; all-in-one installs both. The Hub unit runs the existing combined Hub and dashboard application once. Units use the current Python interpreter, application directory, and config path. They run under the invoking administrator's account; Edge is granted `CAP_NET_RAW` for passive capture. No credentials are copied into the unit files. The local config must remain readable only by its owner.

System service installation and removal need root. Review the requested operation, then run `sudo rocks service install` or `sudo rocks service uninstall`. Start, stop, restart, and status use the configured units:

```bash
rocks service start
rocks service stop
rocks service restart
rocks service status
rocks service uninstall
```

Inspect service output and startup failures with journald:

```bash
journalctl -u rocks-edge.service -f
journalctl -u rocks-hub.service -f
```

To inspect unit generation without installing anything, use `rocks service generate --output-dir /tmp/rocks-units`; this works without systemd. Service management does not configure a switch SPAN session, TAP, router, firewall, or network topology. Broad Edge visibility still requires an appropriate observation point.

## Health and Diagnostics

Run a concise infrastructure check or request detailed diagnostics:

```bash
rocks health
rocks health check
rocks health verbose
```

Health validates the generated config, reports configured systemd service states, checks the Hub health endpoint and dashboard login route where applicable, performs read-only Hub/Edge SQLite probes, checks the Edge buffer, and compares the latest telemetry with the configured freshness window (`health.telemetry_freshness_seconds`, default 300 seconds). Verbose output includes selected non-secret paths, sensor ID, endpoint, capped record counts, telemetry age, and recovery hints. It never prints API keys, passwords, password hashes, session secrets, or SMTP credentials.

`HEALTHY` means all applicable required checks passed. `DEGRADED` means at least one applicable check is warning or a required service state is unknown. `UNHEALTHY` means at least one check reports an error. Components not configured for the deployment mode are `NOT_APPLICABLE` and do not affect overall health. Exit codes are `0` healthy, `1` degraded or unhealthy, and `2` invalid or unavailable configuration.

Service state and telemetry health are separate: an active Edge or Hub process can still have stale or absent telemetry. For a stopped or failed service, check `rocks service status` and the matching `journalctl -u rocks-edge.service` or `journalctl -u rocks-hub.service`. For an unavailable Hub API, check Hub service state, bind URL/port, and connectivity. For stale telemetry, check Edge delivery and verify the configured interface receives traffic from a SPAN/port-mirror session or TAP. ROCKS health diagnoses ROCKS infrastructure only; a healthy result does not mean the monitored network is healthy. Installing ROCKS does not itself provide campus-wide visibility.

## Email Notifications

Email is optional and disabled by default. Configure the existing `email` section in the owner-only `config/config.yaml`, or use `ROCKS_EMAIL_ENABLED=true` with `ROCKS_SMTP_HOST`, `ROCKS_SMTP_PORT`, `ROCKS_SMTP_USERNAME`, `ROCKS_SMTP_PASSWORD`, `ROCKS_SMTP_FROM`, and `ROCKS_SMTP_TO`. Environment values override YAML; with systemd, the generated unit optionally reads the local ignored `.env` file. Keep that file owner-only (`chmod 600 .env`) and never put real credentials in tracked files. For interactive shell use, export the variables in that shell. STARTTLS on port 587 is the default. Implicit TLS is available with `use_ssl: true` and `starttls: false`; certificate verification stays enabled.

By default, only existing `HIGH` alerts trigger messages. Set `minimum_severity: WARNING` to include both existing `WARNING` and `HIGH` severities. Each newly inserted alert receives at most one bounded SMTP attempt. Views, acknowledgements, resolutions, and duplicate alert processing never resend. Email failure records `FAILED` with a safe reason code, leaves the alert `OPEN`, and does not interrupt alert storage. SMTP timeout defaults to five seconds and is capped at 30 seconds.

Test delivery only when explicitly requested:

```bash
rocks alerts email-test
```

This sends a test message only when notifications are enabled and does not create an alert. The dashboard shows `Sent`, `Failed`, `Not sent`, or `Not configured`; it does not expose SMTP credentials. Troubleshoot with `journalctl -u rocks-hub.service`. Email is not required for telemetry analysis or alert creation.

## Detection and Risk Evidence

ROCKS evaluates deterministic metadata rules for `HIGH_TRAFFIC`, `CONNECTION_BURST`, `RECONNAISSANCE_LIKE`, `DNS_ANOMALY`, `RECONNECT_STORM`, and explicitly evidenced `DEAUTH_RELATED` telemetry. Thresholds live under `detection` in `config/config.yaml`; defaults are starting points, not universal values, and should be tuned to each deployment's normal traffic and observation window. `ROCKS_DETECTION_*` environment variables can override individual thresholds. `high_traffic_rate` is observed bytes/second; `connection_burst_rate` and `dns_request_rate` are counts/second over `window_seconds`; destination thresholds are unique IPs/ports in a behavior-summary window; `dns_failure_rate` is the failed/request ratio from available DNS telemetry; reconnect and deauth thresholds are explicit event counts.

Each assessment stores the triggered rule IDs, severity, explanation, and relevant counters/thresholds. `HIGH_TRAFFIC`, `CONNECTION_BURST`, and `DNS_ANOMALY` are `WARNING`; `RECONNAISSANCE_LIKE`, `RECONNECT_STORM`, and evidence-backed real `DEAUTH_RELATED` are `HIGH`; simulated deauth is `WARNING` and visibly marked as simulated. The overall severity is the highest triggered rule severity, promoted to `HIGH` by the existing ML anomaly threshold or `HIGH` retention priority. When the existing ML baseline is ready, its anomaly score and retention priority are reported separately; no new probability or independent combined score is invented. Deterministic rules continue to run without ML. Existing alert IDs still correlate one potential anomaly per telemetry record, and the existing lifecycle and one-time email notification behavior remain unchanged.

`rocks detection status` displays active policy thresholds. `rocks detection test` evaluates safe synthetic examples only; it sends no packets and performs no attacks. The deauthentication example is explicitly marked simulation-only. Real deauthentication-related detection requires explicit 802.11 management-frame evidence; no live parser currently emits that evidence. Reconnaissance-like behavior does not prove a port scan or attack. Thresholds and anomaly scores are investigation aids, not measured accuracy or attack probabilities.

## Python virtual environment

Create a virtual environment from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Install the project

```bash
pip install -e .
```

## Run the CLI

```bash
rocks --help
rocks --version
rocks status
rocks config
rocks logs
rocks test
rocks dashboard status
rocks dashboard run
```

## Run tests

```bash
pytest
```

## Repository purpose

This repository is the initial foundation for ROCKS Fleet and should remain modular so that future chunks can be added without restructuring the project.
