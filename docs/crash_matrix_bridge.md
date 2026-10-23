# Crash Matrix Campaign Bridge

The deterministic chaos campaign is evaluated by the protocol crash matrix rather than by placeholder invariant flags.

- Each seeded schedule step selects one of the seven canonical crash points.
- Normal and binding-substitution steps invoke the same single-point evaluator used by the exhaustive matrix.
- The artifact records each terminal state, effect count, audit count, and invariant result.
- Aggregate invariants are derived from those witnesses: normal executions must converge and substitution executions must fail closed.
- Exact replay regenerates both the schedule and every evaluated witness.
