# Development plan

The project is intentionally planned in chunks so the architecture remains coherent as it grows.

## Chunk 1: Foundation

- repository structure
- Python package setup
- CLI scaffolding
- configuration skeleton
- logging utilities
- path management
- basic tests and documentation

## Chunk 2: ROCKS Edge capture and flow processing

- network observation design
- metadata extraction
- flow feature generation
- local buffering and telemetry preparation

## Chunk 3: Telemetry and local storage

- versioned structured telemetry format
- local SQLite storage and indexed retrieval
- persistent offline buffering
- reliability and duplicate protection

## Chunk 4: ROCKS Hub

- FastAPI telemetry ingestion
- central SQLite storage
- Edge API-key authentication and registry
- health, query, and statistics endpoints
- bounded Edge sender using the local buffer

## Chunk 5: ML baseline, anomaly scoring, and retention scoring

- local time-aware baseline learning from historical behavior summaries
- expected traffic estimation and bounded anomaly scoring
- LOW/MEDIUM/HIGH retention prioritization
- explicit training and lightweight inference
- no destructive deletion or attack classification

## Chunk 6: Command Center dashboard

- read-only administrator dashboard
- authenticated session-based access
- Edge, telemetry, event, traffic, storage, and ML status views
- bounded JSON polling for live refresh

## Chunk 7: MVP integration, safe simulator, and alerting

- controlled synthetic telemetry generation
- deterministic end-to-end demonstration
- local investigation alert persistence and dashboard display
- no attack traffic, automatic blocking, or email by default

## Chunk 24: Demo and simulation workflow

The demo workflow is intentionally synthetic and operator-friendly. It runs through the existing ROCKS pipeline without touching production data or requiring a physical network interface:

```bash
rocks demo --mode normal
rocks demo --mode anomaly
rocks demo --mode full
rocks simulate --scenario high_traffic --count 5
rocks simulate --scenario reconnaissance_like
rocks simulate --scenario deauth_related_simulation
```

Supported scenarios are `normal`, `high_traffic`, `reconnaissance_like`, `dns_anomaly`, `reconnect_storm`, `deauth_related_simulation`, and `mixed_anomalous`. Each scenario uses the project's existing simulator, preserves the `simulation=true` marker for synthetic events, and keeps all telemetry clearly separated from real network observations. The demo does not run scans, packet injections, deauthentication frames, firewall changes, or any other dangerous network action.

## Chunk 8: Integration, deployment, testing, and hardening

- end-to-end validation
- deployment packaging
- production hardening
- operational testing and documentation updates

Chunk 8 live Edge operation is implemented as part of the existing Edge layer: `rocks edge run`, local-first buffering, bounded Hub sending, dry-run mode, and graceful shutdown.
