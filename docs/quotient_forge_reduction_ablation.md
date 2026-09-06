# QuotientForge real-backend reduction ablation

K7-07f applies the reduction-disabled and reduction-enabled versions of one frozen semantic case to the production CEGIS, SMT, and QBF paths. It records observations without manufacturing synthetic work units or suppressing negative results.

## Frozen pair

The two `SynthesisProblem` values must have identical horizons, plant states, transition topology, environment inputs, semantics, faults, observers, initial pairs, and outputs. Only the transition machine-symbol assignment and symbol-domain size may differ. The reduced symbol domain may not be larger.

The artifact binds both problem fingerprints and the K7-07 quotient, preservation, lift, and small-model solution-set evidence digests. Source state count, quotient class count, symbol count, and machine-state bound are recorded as exact before/after changes.

## Actual calls

- CEGIS invokes the production in-process exhaustive CEGIS search twice and records generated candidates, independent checker calls, and counterexample blockers from `SearchStats`.
- SMT invokes the production external solver adapter twice. Solver rounds and accepted hard blockers come from its runtime artifact; candidate and checker counts are reported only when derivable, otherwise `NOT_VERIFIED`.
- QBF compiles each actual bounded game, invokes either the pinned external adapter or the production in-process QBF reference backend, and independently checks any returned candidate. Variable and clause counts come from the QDIMACS artifact.

Wall time is observed around each production call. Linux peak memory is the harness process `VmHWM`, not per-backend isolated memory. Other platforms, including Windows, are explicitly `NOT_VERIFIED`. QBF blockers are `UNSUPPORTED` because the backend is not blocker-driven.

## Gates

A conclusive SAT/UNSAT disagreement or an unchecked SAT candidate sets `semantic_gate` to `disable`; reduction is never enabled in that state. Timeout, resource exhaustion, solver absence, unknown, malformed output, and disabled execution remain distinct and produce an inconclusive gate rather than an invented decision.

Performance values are always retained, including equal runtime and regressions. `performance_signal` is descriptive only and `performance_claimed` is fixed to `false`; a single ablation artifact is not a publication-level performance claim.

The manifest writer emits one top-level manifest and one result for each backend/toggle pair under `backends/<backend>/{disabled,enabled}.json`. Generated runs belong under ignored artifact directories and are not committed.
