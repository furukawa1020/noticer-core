# K10 QuotientOdometer Replication and Go / Pivot / Kill Gate

This package fixes a non-compensatory decision rule: `KILL > PIVOT > GO`. A single fatal observation cannot be offset by successful engineering results. Missing GO evidence or unknown KILL evidence produces `PIVOT`, never `GO`.

## Reproduction

Generated files belong under `artifacts/k10_quotient_odometer/replication/` and are not committed.

```bash
python tools/validate_quotient_odometer_package.py manifest --commit <FULL_GIT_SHA> --out artifacts/k10_quotient_odometer/replication/manifest.json
python tools/validate_quotient_odometer_package.py blank-evidence --out artifacts/k10_quotient_odometer/replication/evidence.json
python tools/validate_quotient_odometer_package.py decide --evidence artifacts/k10_quotient_odometer/replication/evidence.json --manifest-sha256 <MANIFEST_SHA256> --out artifacts/k10_quotient_odometer/replication/decision.json
python tools/validate_quotient_odometer_package.py validate --manifest artifacts/k10_quotient_odometer/replication/manifest.json --report artifacts/k10_quotient_odometer/replication/decision.json
```

Blank evidence intentionally yields `PIVOT`. Every observation must bind to an external artifact SHA-256. Raw biosignal, baseline, subject ID, stable identifier, and secret key fields are prohibited. Hardware remains `NOT_VERIFIED`; software CI is not physical deployment evidence.

## Rejection boundary

`KILL` includes post-release enforcement, rollback loss, marginal-for-joint substitution, adaptive unsoundness, receipt forgery, stale profile reuse, accounting underflow, held-out bound violations, absence of independent audit, and reduction to a generic counter. These conditions require withdrawing the central claim rather than relabeling a failed result.
