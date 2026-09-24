# QuotientLimit Evaluation Protocol v1

## Freeze rule

This protocol and `configs/quotient_limit/k9_ql_research_v1.toml` are frozen
before K9-QL optimization results are generated. Later work may fix an
implementation defect with an explicit migration record, but must not weaken a
gate, move a family across splits, or reinterpret a result class after seeing a
result.

## Registered scope

- at least 24 benchmark families, with at least 8 held-out families
- at least 2 private histories in every model
- explicit-trace horizon support through at least 16
- sequence-form horizon gate of at least 64
- at least 4 services in the collusion gate
- at least 4 fault families
- separate exact, total-variation, and rational rho-delta privacy modes
- at least 2 solver backends when installed
- a mandatory exact rational certificate path

The family, not an instance or matrix row, is the split unit. Generated
variants inherit the family split. Held-out families cannot guide objective,
constraint, solver, reconstruction, or checker design.

## Formulation protocol

The explicit trace LP is the small-model semantics oracle. The sequence-form LP
is the scalable formulation. On registered cross-check cases they must agree on
feasibility and exact objective value after rational checking. A mismatch is a
failure, not an averaging opportunity.

The following are fixed independently:

- model and quotient canonicalization
- observer projection and collusion membership
- privacy mode and rational parameters
- utility, readiness, deadline, and fault obligations
- objective order and integer cost scale
- resource limits and timeout interpretation

## Certification protocol

Solver output is untrusted candidate material. The independent checker parses a
bounded canonical `.qlc` envelope, binds all model and matrix domains, and uses
exact rational arithmetic. It rejects malformed values, oversized integers,
non-canonical bytes, domain substitution, violated primal constraints, invalid
dual bounds, and invalid infeasibility witnesses.

The classifications are deliberately non-interchangeable:

- solver infeasible does not imply `CERTIFIED_INFEASIBLE`
- solver optimal does not imply `CERTIFIED_OPTIMAL`
- timeout does not imply infeasible
- a small floating residual does not imply an exact certificate
- an attack near chance does not imply privacy

## Evaluation matrix

The frozen scalability axes are histories `2,4,8,16,32,64`, quotient classes
`1,2,4,8`, horizons `4,8,16,32,64,128`, services `1,2,4,8`, observer counts
`1,2,4,8`, and fault scenarios `1,4,8,16`. Experiments record variables,
equalities, inequalities, nonzeros, solver time, rational reconstruction time,
checker time, memory, and certificate size.

Required ablations compare explicit and sequence formulations, quotient and
observer reductions, floating and exact paths, certificate paths, marginal and
joint collusion, per-bucket and longitudinal models, and deterministic and
randomized mechanisms.

## Reproducibility and artifacts

Every run records the Git commit, canonical contract digest, model digest,
matrix digest, solver identity and version, platform, seed, limits, status, and
checker result. Generated outputs belong below
`artifacts/k9_quotient_limit/` and are not committed. No artifact may contain a
private biosignal, baseline, stable identifier, or undeclared private field.

Canonical serialization sorts maps and uses explicit hash domains. Repeating a
solver-free checker run over identical bytes must produce identical results on
Windows and Linux.

## Go / Pivot / Kill interpretation

`GO` requires exact checker agreement, mutation rejection, certified feasible
and infeasible cases, held-out execution, collusion counterexamples, empirical
attack consistency, and the registered scalability gate. `PIVOT` narrows the
claim while retaining valid lower-bound or checker results. `KILL` applies when
only floating solver output remains, causality can inspect private futures,
utility is met by suppressing actions, collusion is replaced by marginal
privacy, or no independently checkable optimality or infeasibility result can
be produced.

Hardware energy and physical deployment claims remain `NOT_VERIFIED`.

