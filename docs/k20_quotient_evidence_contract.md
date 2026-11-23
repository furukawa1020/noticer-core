# K20 QuotientEvidence Research Contract

## Status

This document freezes the research contract for K20. It defines what the
repository may claim before any real biosignal experiment is run. It does not
report a scientific result.

## Research question

For two private biosignal histories with the same authorized action semantics,
does an AETP release mechanism reduce an adaptive observer's ability to infer
identity or link sessions while preserving the authorized action, its deadline,
and operational utility?

## Primary claim

K20 may authorize the following claim only when every required evidence gate
passes:

> Under the frozen threat model, dataset manifest, session-disjoint split, and
> attacker suite, the evaluated AETP mechanism reduces identity inference or
> cross-session linkability relative to the named baseline while satisfying the
> pre-registered action-utility non-inferiority margin.

The claim is scoped to the evaluated population, sensors, sessions, release
mechanisms, attackers, and operating conditions. It is not a claim of universal
anonymity, cryptographic indistinguishability, or protection against an
unmodelled observer.

## Evidence classes

| Class | Permitted use | Scientific claim |
|---|---|---|
| `fixture` | UI, serialization, and deterministic pipeline tests | Forbidden |
| `synthetic-control` | Positive and negative harness validation | Harness-only |
| `pilot` | Protocol debugging and variance estimation | Exploratory only |
| `registered-experiment` | Frozen confirmatory evaluation | Eligible |
| `external-replication` | Independent reproduction of a frozen experiment | Eligible and separately labelled |

Every public artifact MUST state its evidence class. A fixture or synthetic
control MUST NOT be rendered with wording that implies a measured privacy gain.

## Verdict lattice

K20 uses four terminal verdicts:

- `invalid`: the input, manifest, split, provenance, or protocol contract is
  malformed. No result is interpreted.
- `inconclusive`: the contract is valid, but evidence is insufficient, an
  interval crosses the frozen decision boundary, or execution is cut off.
- `failed`: sufficient valid evidence contradicts at least one authorized
  claim gate.
- `verified`: every mandatory validity, privacy, utility, multiplicity,
  provenance, and reproducibility gate passes.

The ordering is intentionally non-monotonic. Neither `invalid` nor
`inconclusive` can be promoted to `verified` by retry count, UI state, missing
value imputation, or manual override. A new run with a new artifact identity is
required.

## Mandatory validity gates

A registered experiment is valid only if all of the following hold:

1. Subjects and sessions have stable opaque identifiers.
2. No session identifier occurs in more than one split.
3. Feature fitting, calibration, and threshold selection use training data only.
4. The attacker never receives a private field excluded by the frozen release
   surface.
5. Dataset, configuration, code, environment, and seed digests are recorded.
6. Baseline and treatment runs share paired inputs and declared randomness.
7. Censoring, exclusions, failures, and missing measurements are disclosed.
8. The positive synthetic control succeeds and the permutation control remains
   near its pre-registered chance boundary.

Random window splitting is prohibited even when windows do not overlap.

## Mandatory claim gates

The primary claim requires all of the following:

- at least one pre-registered identity or linkability endpoint;
- a paired effect estimate with a cluster-aware uncertainty interval;
- correction for the frozen family of confirmatory comparisons;
- a practically meaningful privacy-effect threshold;
- action-semantic equivalence;
- utility non-inferiority;
- deadline and liveness compliance;
- complete Attack-to-Evidence Matrix coverage;
- a reproducible, integrity-bound public artifact capsule.

Passing a privacy endpoint cannot compensate for failing action semantics,
safety, liveness, or utility.

## Required comparisons

The confirmatory matrix MUST name and execute, when applicable:

1. immediate release;
2. encryption only;
3. padding only;
4. fixed-rate release;
5. AETP release;
6. the complete protected stack.

Unsupported comparisons are marked `not-applicable` with a reason; they are not
silently omitted.

## Reproducibility identity

Each run is identified by a digest over the canonical experiment manifest,
dataset manifest, split assignment, implementation revision, environment lock,
attacker definitions, release-mechanism definitions, and seed ledger. A changed
component creates a distinct run identity.

## Falsification conditions

The primary claim is falsified for the evaluated scope if any pre-registered
condition below holds:

- an AETP identity or linkability endpoint is not better than its named baseline
  by the meaningful-effect threshold;
- the confidence interval crosses the frozen privacy decision boundary;
- action semantics differ between paired private histories;
- utility violates its non-inferiority margin;
- latency or liveness violates the frozen operational bound;
- a stronger in-scope attacker reverses the conclusion;
- the result cannot be reproduced from the public capsule.

Falsification is retained as a first-class result and MUST NOT be rewritten as
`inconclusive` after observing the outcome.

## Publication language

Permitted descriptions include `candidate new primitive`, `proposed security
notion`, `to the best of our literature review`, and `we found no prior work
combining these exact semantics`.

The repository, demo, and manuscript MUST NOT state `world-first` without a
separate completed literature and patent review.

## Change control

Any change to endpoints, margins, exclusions, attackers, split rules, or claim
wording after confirmatory data inspection creates a new contract version. The
previous contract and result remain addressable. Retroactive replacement is
forbidden.
