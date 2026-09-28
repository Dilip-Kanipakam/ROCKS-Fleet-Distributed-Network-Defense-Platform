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

## Chunk 7: Safe traffic/anomaly simulator

- controlled simulated traffic generation
- evaluation of detection workflows
- safe testing without live network risk

## Chunk 8: Integration, deployment, testing, and hardening

- end-to-end validation
- deployment packaging
- production hardening
- operational testing and documentation updates
