# Action-Quotient Release Polytope (AQRP)

## Status

This document freezes the K9-QL-00 research object before optimization results
are observed. QuotientLimit is a candidate action-quotient lower-bound
framework, not a claim of a first or universally optimal privacy mechanism.

## Research question

For a finite causal release system whose private histories are quotiented by
authorized action semantics, what is the minimum observable cost required to
preserve exact or approximate action-equivalent trace privacy while satisfying
action, deadline, and bounded-fault utility?

## Finite model

A model fixes all of the following before solving:

- a non-empty finite set of private histories `H`
- an action quotient `Q` and total map `class_of: H -> Q`
- a finite public information tree and horizon
- private readiness and public admission semantics
- a finite release alphabet
- declared observer projections, including joint collusion projections
- authorized-action, deadline, and fault obligations
- one privacy mode and one lexicographically ordered cost model

Histories in one quotient class agree on authorized action sequence, service,
public action window, policy, public deadline, and public fault contract. They
may differ in private readiness, evidence margin, private state, baseline
distance, and private failure path. Histories with different authorized action
semantics must not be merged to make privacy easier.

## Causality boundary

A mechanism is a behavioral strategy over public information sets. Nodes in
the same information set use the same release distribution. An information set
may depend only on the public prefix, admitted quotient prefix, public fault
prefix, and current slot. It must not depend on a private history identifier,
future readiness, future faults, hidden private state, or an action class before
public admission.

Private readiness `r(h)`, public admission cutoff `c(q)`, and public release
window `[a(q), d(q)]` satisfy:

```text
r(h) <= c(q) < a(q) <= d(q)
```

The public values `c(q)`, `a(q)`, and `d(q)` are constant inside a quotient
class. This separation prevents a release rule from declassifying exact private
readiness while preserving authorized action utility.

## Polytope

For a fixed finite model, mechanism variables `x` encode probability flow over
information-set decisions. The Action-Quotient Release Polytope is:

```text
P = { x |
      Causality(x)
  and ProbabilityFlow(x)
  and Privacy(x)
  and Utility(x)
  and FaultSafety(x)
  and x >= 0 }
```

The objective is `minimize c^T x` for the frozen cost vector. Under linear
privacy, utility, fault, and cost constraints, `P` is a convex polytope. This
statement applies only to the finite model above; it is not extended to general
infinite-state or nonlinear systems.

## Privacy modes

For action-equivalent histories `h0 ~A h1`, every declared observer `o`, and
every observable trace `y`:

- `Exact`: observed trace probabilities are equal.
- `TotalVariation(tau)`: their total variation distance is at most rational
  `tau`.
- `RhoDelta(rho, delta)`: both directed hockey-stick divergences are bounded by
  rational `delta`, with rational `rho >= 1`.

Certificates retain rational `rho`; `epsilon = ln(rho)` is report-only. Privacy
modes are evaluated separately and are never silently mixed.

## Result boundary

QuotientLimit reports exactly one of:

```text
CERTIFIED_OPTIMAL
CERTIFIED_INFEASIBLE
FEASIBLE_UNCERTIFIED
INCONCLUSIVE_NUMERIC
TIMEOUT
RESOURCE_LIMIT
INVALID_MODEL
```

An external solver is outside the trusted computing base. `CERTIFIED_OPTIMAL`
requires an exact rational primal witness and matching dual lower-bound witness.
`CERTIFIED_INFEASIBLE` requires an exact infeasibility witness. A solver status,
small floating residual, timeout, or exhausted search is not a certificate.

## Explicit non-goals

This finite framework does not claim a general privacy optimizer, an
infinite-horizon solution, nonlinear utility optimization, physical RF or
microarchitectural protection, real sensor authenticity, hardware energy
proofs, medical validity, or arbitrary differential privacy or Pufferfish
composition.

