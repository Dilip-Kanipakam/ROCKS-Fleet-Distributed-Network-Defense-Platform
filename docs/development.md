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

- telemetry ingestion
- central data storage
- detection orchestration
- service exposure for the dashboard

## Chunk 5: ML baseline, anomaly scoring, and retention scoring

- learning time-dependent baselines
- unusual traffic spike detection
- anomaly score generation
- telemetry retention priority support to reduce storage use

## Chunk 6: Safe traffic/anomaly simulator

- controlled simulated traffic generation
- evaluation of detection workflows
- safe testing without live network risk

## Chunk 7: Command Center dashboard

- administrator-facing dashboard
- view detections and telemetry summaries
- secure operations and workflow support

## Chunk 8: Integration, deployment, testing, and hardening

- end-to-end validation
- deployment packaging
- production hardening
- operational testing and documentation updates
