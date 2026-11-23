# K20 AETP Threat Hypotheses and Falsification Protocol

## Scope

This protocol freezes the adversary, observable release trace, hypotheses, and
counterexample rules used by K20. It complements the K20 research contract and
does not claim that AETP has already passed an experiment.

## Protected secrets

The evaluated secrets are:

- subject identity;
- whether two sessions belong to the same subject;
- private biosignal history beyond the authorized action semantics;
- session membership when membership inference is explicitly enabled.

The authorized action itself, declared public context, mechanism version, and
published operational bounds are not secrets.

## Observable trace

An attacker receives only fields listed in the frozen release-surface manifest.
The surface may include packet time, direction, length bucket, release outcome,
public action, retransmission marker, and public error class. Payload plaintext,
private evidence, internal state, raw biosignal values, keys, and unlisted debug
fields are forbidden inputs.

An experiment is `invalid` if the attacker observes a forbidden field, even if
that field is later removed from the reported feature-importance plot.

## Action equivalence

Two private histories are action-equivalent only when the frozen policy maps
both histories to the same complete public action semantics, including action
kind, parameters, deadline class, safety disposition, and recovery obligation.
Matching a display label alone is insufficient.

All primary AETP comparisons are conditioned on action equivalence. Comparisons
across different authorized actions measure a different property and MUST be
reported separately.

## Adversary classes

K20 evaluates the following nested classes:

| ID | Knowledge and capability |
|---|---|
| `A0` | Public priors and action labels only |
| `A1` | `A0` plus individual release events |
| `A2` | `A1` plus timing, ordering, direction, and length metadata |
| `A3` | `A2` plus multiple sessions and adaptive feature construction |
| `A4` | `A3` plus mechanism source, training procedure, and auxiliary sessions allowed by the manifest |

An in-scope stronger adversary supersedes a weaker result. Success against `A1`
does not authorize a claim against `A3` or `A4`.

## Primary hypotheses

### H1: Identity inference reduction

Within each action-equivalence class, the strongest frozen in-scope attacker
has lower subject-identification performance against AETP than against the named
baseline by at least the pre-registered meaningful-effect threshold.

### H2: Cross-session unlinkability improvement

Within each action-equivalence class, AETP lowers pairwise same-subject
linkability relative to the named baseline by the frozen threshold.

### H3: Action utility non-inferiority

AETP preserves action correctness, deadline compliance, and liveness within
their frozen non-inferiority margins.

### H4: Control validity

The identity-positive synthetic control is learnable, while the label-broken
permutation control remains inside its frozen chance interval. Failure of either
control makes the corresponding experiment `invalid`, not a privacy success.

## Attacker training contract

- Splits are disjoint by session before window extraction or feature fitting.
- Hyperparameter selection and probability calibration use training data only.
- Test labels are inaccessible until the attacker and threshold are frozen.
- Every attacker receives the same permitted surface for paired mechanisms.
- Failed attacker runs and constant predictors remain in the execution ledger.
- A resource limit is declared before execution.

Resource exhaustion yields `inconclusive`. It does not establish privacy.

## Counterexample trace

The first discovered violation is serialized as the shortest reproducible trace
under the frozen reduction order. It includes:

- slot index;
- public input;
- left private-state identifier;
- right private-state identifier;
- left observable event;
- right observable event;
- authorized action semantics on both sides;
- violated hypothesis;
- mechanism and manifest digests.

If two traces have equal length, canonical lexical ordering selects the retained
trace. Counterexamples are retained even when a later mechanism version passes.

## Verdict rules

| Condition | Verdict |
|---|---|
| Malformed input, split overlap, forbidden feature, digest mismatch | `invalid` |
| Valid execution cut off, underpowered interval, unsupported endpoint | `inconclusive` |
| Valid sufficient evidence violates a frozen boundary | `failed` |
| Every mandatory hypothesis and evidence gate passes | `verified` |

No aggregation rule may convert `invalid` or `inconclusive` into `verified`.
Missing cells in an Attack-to-Evidence Matrix remain visible.

## Falsification protocol

A scoped AETP claim is falsified when a valid confirmatory run establishes any
of the following:

1. the strongest frozen attacker retains an identity or linkability advantage
   outside the permitted bound;
2. AETP is not meaningfully better than its named baseline;
3. action semantics diverge for a paired history;
4. utility, deadline, safety, or liveness crosses its non-inferiority boundary;
5. the result depends on session overlap, test-set tuning, or a forbidden field;
6. an integrity-valid public capsule cannot reproduce the reported decision.

Conditions 1 through 4 produce `failed`. Conditions 5 and 6 produce `invalid`
until a distinct corrected experiment is registered and executed.

## Known non-goals

K20 does not promise protection against sensor compromise, endpoint compromise,
key extraction, denial of service, unlimited auxiliary information, or an
observer outside the frozen release surface. These remain explicit limitations,
not evidence that the evaluated hypotheses passed.
