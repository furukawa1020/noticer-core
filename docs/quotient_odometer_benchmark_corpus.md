# QuotientOdometer Frozen Benchmark Corpus

QO-15 fixes a deterministic benchmark contract for QuotientOdometer. It is an engineering evaluation corpus, not scientific evidence by itself.

## Split discipline

- Cases are assigned by `family_id`; a family may never cross development and held-out splits.
- Development cases expose their oracle expectation for implementation and calibration.
- Held-out cases expose neither oracle expectation nor calibration visibility.
- Case IDs, family IDs, procedural seeds, order, and dimensions contribute to a deterministic fingerprint.

## Required coverage

Both splits contain at least two independent families for each of exact, approximate, adaptive, concurrent, coalition, longitudinal, and crash accounting. Gates additionally require adaptive selectors, crash schedules, 512-round longitudinal scale, multi-service concurrency, and multi-principal coalitions.

`validate_frozen_corpus` fails closed on duplicate IDs or seeds, family leakage, oracle leakage, missing axis coverage, and insufficient scale. The corpus intentionally contains no biosignal data and makes no world-first claim.
