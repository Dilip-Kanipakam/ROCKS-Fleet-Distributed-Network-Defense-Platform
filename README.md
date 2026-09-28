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

ROCKS Edge is the observation layer. In future chunks, it will be responsible for reading network metadata from mirrored traffic, extracting flow information and features, buffering local data, and forwarding structured telemetry to the Hub. This chunk does not implement packet capture or edge data collection.

## ROCKS Hub

ROCKS Hub is the centralized collection and analysis layer. Future Hub functionality will include receiving telemetry, storing it, running detection logic, and exposing services to the dashboard. This chunk does not implement the Hub.

## Command Center

The Command Center is the administrator dashboard for investigation, monitoring, and operational awareness. It is planned for a future chunk and is not implemented here.

## Metadata-first approach

ROCKS is designed around metadata and flow features instead of packet payload storage. This keeps the system more privacy-conscious, reduces storage overhead, and better matches the project's low-cost, self-hosted monitoring goals.

## Future ML purpose

Machine learning is planned for a later chunk and will be used to:

- learn time-dependent network traffic baselines
- detect unusual traffic spikes
- generate anomaly scores
- help prioritize telemetry retention to reduce storage use

No ML implementation is included in this foundation chunk.

## Current development status

This repository currently contains only the foundation for ROCKS Fleet:

- project structure
- Python package metadata
- configurable CLI
- configuration and logging scaffolding
- documentation and test baseline

Chunk 1 is intentionally limited to project foundation work. It does not implement packet capture, the Hub, the dashboard, or ML features.

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
```

## Run tests

```bash
pytest
```

## Repository purpose

This repository is the initial foundation for ROCKS Fleet and should remain modular so that future chunks can be added without restructuring the project.
