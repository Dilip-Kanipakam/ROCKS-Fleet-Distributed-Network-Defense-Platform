# ROCKS Fleet architecture

This document describes the planned architecture of ROCKS Fleet without implying that unfinished components are already implemented.

## High-level design

The intended flow is:

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

## Core responsibilities

### ROCKS Edge

ROCKS Edge is the observation layer. It is intended to handle network observation, extraction of metadata and flow features, local buffering, and sending structured telemetry to the Hub.

### ROCKS Hub

ROCKS Hub is the centralized analysis layer. It is intended to receive telemetry, store it, run detection logic, and host services that support the Command Center dashboard.

### Command Center

The Command Center is the administrator dashboard. It provides a safe operational interface to review detections and network posture without taking automated blocking actions.

## Metadata-first design

ROCKS is planned as a metadata-first system. It does not rely on packet payload storage. The design emphasis is on flow metadata, device behavior, and risk-oriented analysis rather than deep packet inspection.

## Deployment model

The project is designed to scale from a single Linux all-in-one deployment to a distributed deployment with multiple Edge sensors connected to one central Hub.

## Current status

Chunks 2 and 3 implement Edge observation, versioned metadata-only telemetry, local SQLite storage, and a persistent offline buffer.

Chunk 4 adds the ROCKS Hub API as the central ingestion boundary. It validates the existing telemetry schema, authenticates registered Edge sensors with hashed API keys, stores records in a dedicated indexed SQLite database, and provides health, query, registry, and statistics endpoints. The Edge sender uses the existing local buffer and removes records only after acknowledgement.

The Hub does not perform packet capture. It serves the read-only Command Center from the same FastAPI process.

Chunk 5 adds the local ML layer after Hub storage:

```text
Telemetry
  -> historical baseline
  -> time-aware expected traffic
  -> actual versus expected deviation
  -> anomaly score
  -> retention score and LOW/MEDIUM/HIGH storage priority
```

The model uses existing behavior-summary fields and time-of-day/day-of-week features. It identifies behavior that differs from the learned baseline; it does not prove that an attack occurred. A new deployment needs enough historical telemetry before the baseline is meaningful.

Chunk 6 adds the administrator-facing Command Center. It uses signed sessions, bounded read-only queries, and local Jinja2 templates. Dashboard views expose health, Edge status, telemetry metadata, analysis events, retention priorities, and traffic history without exposing credentials or enabling network enforcement.

Chunk 7 completes the local MVP integration with deterministic synthetic telemetry scenarios and a lightweight alert engine. Alerts are generated from existing ML analysis results when anomaly or retention thresholds are crossed, stored in the existing Hub database, and exposed through the read-only dashboard. They are investigation signals, not attack classifications.

The live Edge agent in Chunk 8 composes the existing Edge modules into one process. It captures metadata from an authorized interface, creates bounded feature summaries, persists telemetry locally, buffers it durably, and sends acknowledged records to the Hub. The Hub is optional at runtime; local buffering remains the reliability boundary.
