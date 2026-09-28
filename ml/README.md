# ROCKS ML

ROCKS ML is a local Hub-side analytics layer. It learns a lightweight time-aware baseline from `BEHAVIOR_SUMMARY` telemetry, estimates expected traffic, compares actual traffic with that expectation, and calculates anomaly and storage-retention scores.

## Current behavior

- Uses hour of day, day of week, and existing behavioral telemetry features
- Requires at least 20 historical samples by default
- Uses a deterministic `RandomForestRegressor` with a fixed random seed
- Stores models locally as configurable Joblib files
- Produces anomaly scores and retention priorities only
- Does not claim that an attack occurred

Retention priorities are storage guidance only: `LOW`, `MEDIUM`, or `HIGH`. Low scores are not automatically deleted. The Hub continues accepting telemetry when the baseline is not ready or analysis fails.

Run the local demonstration with:

```bash
rocks ml test
```

ML processing is self-hosted. No external AI service, payload storage, automatic blocking, dashboard, or simulator is included.
