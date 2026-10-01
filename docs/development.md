# Development

## Project structure

```text
config/                 YAML template and runtime configuration location
dashboard/              Dashboard documentation
docs/                   Architecture, deployment, development, and API docs
src/rocks/
  edge/                 Capture, parsing, flows, features, telemetry, buffer
  hub/                  FastAPI app, auth, registry, storage, investigations
  detection/            Deterministic rules and assessments
  alerts/               Alert persistence projection and optional email
  dashboard/            Authenticated pages, APIs, templates, static assets
  ml/                   Local baseline analysis and retention signals
  simulator/            Bounded synthetic telemetry scenarios
tests/                  Unit, component, dashboard, and integration tests
```

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
rocks --help
```

The package declares Python `>=3.10`. `requirements.txt` mirrors the repository environment; the editable install is the normal setup path.

## Testing and validation

Run the complete suite:

```bash
.venv/bin/python -m pytest -q
```

Run a focused slice while iterating:

```bash
.venv/bin/python -m pytest -q tests/test_integration.py
.venv/bin/python -m pytest -q tests/test_edge.py tests/test_hub.py
.venv/bin/python -m pytest -q tests/test_dashboard.py tests/test_investigation.py
```

Compile source and tests:

```bash
.venv/bin/python -m compileall src tests
```

Safe CLI checks:

```bash
rocks edge test
rocks detection test
rocks ml test
rocks demo --mode normal
rocks simulate high_traffic --count 1
```

These commands do not require live network traffic. The full suite covers foundation/setup, Edge observation, telemetry, buffering, Hub authentication/storage, detection, ML, alerts, dashboard sessions and views, investigations, simulator/demo behavior, and end-to-end flow.

## Adding tests

Keep tests deterministic and local. Use `tmp_path` for SQLite databases and `TestClient` with `create_app(...)` for Hub/dashboard integration. Synthetic telemetry should use the existing constructors and simulator scenarios. Do not use real network interfaces or external services in tests. Add coverage for both successful flow and bounded validation/failure behavior when changing an API or storage contract.

## Coding workflow

1. Identify the owning module and nearby tests.
2. Preserve the metadata-first, local-first architecture and public API contracts.
3. Make the smallest focused change.
4. Run the narrowest relevant test first.
5. Run the full suite, compileall, and `git diff --check` before review.
6. Inspect `git status` and the diff; do not include unrelated work.

Do not commit credentials or generated runtime databases. Do not use live capture or external network activity to validate synthetic features.

## Useful commands

```bash
rocks status
rocks config
rocks health verbose
rocks edge status
rocks hub status
rocks dashboard status
rocks detection status
rocks alerts status
rocks ml status
rocks service status
rocks --help
```

For API and endpoint details, see [investigation-api.md](investigation-api.md) and the root [README.md](../README.md).

## Debugging

- Use `rocks health verbose` for configuration, endpoint, database, buffer, service, and telemetry-freshness diagnostics.
- Use `rocks service status` and `journalctl -u rocks-hub.service` or `journalctl -u rocks-edge.service` for systemd startup issues.
- Use `rocks edge run --dry-run` before live capture.
- Inspect temporary test databases through the failing test or storage API rather than modifying tracked `data/` files.
- For dashboard failures, verify administrator configuration and inspect the first failing focused test.

ROCKS logs and diagnostics must not contain API keys, passwords, session secrets, SMTP credentials, or raw packet payloads.

## Contribution workflow

Keep changes scoped to the requested chunk, add or update tests for behavior changes, document new user-facing commands, and report exact validation commands. Reviewers should check architecture boundaries, authentication, bounded inputs, synthetic-only test behavior, and the absence of automatic network enforcement. Commit and push only when explicitly requested by the project owner.
