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

Optional scenario generation is available with `rocks simulate normal`, `rocks simulate anomaly`, and `rocks simulate mixed`. Dashboard alerts are investigation-only. Email is disabled and not implemented in this MVP.

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
