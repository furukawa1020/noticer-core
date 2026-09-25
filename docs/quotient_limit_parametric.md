# QuotientLimit Parametric Lower Bound

The first parametric engine is intentionally limited to the finite single-action readiness model. It does not claim to be a complete parametric LP solver.

For ready span `R` and deadline `D`, it emits two exact regions:

- `D < R`: infeasible.
- `D >= R`: feasible with minimum worst-case latency lower bound `R`.

The critical threshold is `D = R`. Observer resolution, cover budget, fault count, and service count remain explicit inputs; this first theorem reports that only `R` and `D` are active in this frontier rather than silently discarding the other dimensions.

The matching Lean 4 development proves deadline infeasibility, boundary feasibility, the frontier lower-bound statement, and the latest-readiness support theorem without `sorry`.
