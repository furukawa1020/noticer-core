# K10 QuotientGuard Replication and Go / Pivot / Kill Gate

This package freezes a non-compensatory runtime decision rule: `KILL > PIVOT > GO`. Missing GO evidence or unknown KILL evidence produces `PIVOT`; no successful benchmark can compensate for a fatal runtime safety observation.

Generated artifacts are written under `artifacts/k10_quotient_guard/replication/` and are not committed.

```bash
python tools/validate_quotient_guard_package.py manifest --commit <FULL_GIT_SHA> --out artifacts/k10_quotient_guard/replication/manifest.json
python tools/validate_quotient_guard_package.py blank-evidence --out artifacts/k10_quotient_guard/replication/evidence.json
python tools/validate_quotient_guard_package.py decide --evidence artifacts/k10_quotient_guard/replication/evidence.json --manifest-sha256 <MANIFEST_SHA256> --out artifacts/k10_quotient_guard/replication/decision.json
python tools/validate_quotient_guard_package.py validate --manifest artifacts/k10_quotient_guard/replication/manifest.json --report artifacts/k10_quotient_guard/replication/decision.json
```

Blank evidence intentionally yields `PIVOT`. Each observation binds to an external artifact SHA-256. Raw biosignal, individual private state, differing shadow index, subject identifier, and secret keys are prohibited. Polar hardware remains `NOT_VERIFIED`; recorded/live software adapter success is not physical deployment evidence.

Fatal conditions include private-state exposure, release after divergence, automatic sink recovery, binding bypass, capsule rollback, slot replay, shadow-index exposure, held-out attack escape, reporting resource exhaustion as success, and reduction to a generic monitor. Any one requires withdrawal of the central runtime claim.
