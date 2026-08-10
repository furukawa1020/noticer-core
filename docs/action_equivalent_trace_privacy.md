# Action-Equivalent Trace Privacy (AETP)

Status: proposed security notion and K2 implementation smoke  
Last Updated: 2026-08-10

## Definition

Let `H` be a private biosignal history, `P` a public release policy, and `Phi_P` the only
authorized declassification function. Its output `A = Phi_P(H)` is the complete allowed action
semantics. Two histories are action-equivalent when:

```text
H0 ==_A H1  iff  Phi_P(H0) = Phi_P(H1)
```

The observable trace includes token bytes, packet time, packet size, silence, retries, failures,
and repeated releases. A mechanism satisfies strict AETP when, for every action-equivalent pair:

```text
Law(R(H0; P)) = Law(R(H1; P))
```

Equivalently, the release mechanism factors through the action quotient:

```text
A = Phi_P(H)
R = G_P(A, U)
U independent of H given A and P
```

The implementation therefore makes private evidence unavailable to the Low Side, rather than
asking a Low Side component to ignore evidence it could access.

## What the action semantics include

Action semantics are the information deliberately released by policy: registered action code,
policy binding, and policy-authorized release slot. They do not include evidence magnitude,
score, p-value, embedding, baseline state, identity, cause, or raw physiological time.

AETP does not claim that the action semantics are harmless. Evaluation separates:

```text
allowed leakage = Leakage(S; A)
excess leakage  = Leakage(S; R | A)
```

## Implementation boundary

```text
PRIVATE HIGH SIDE                     LOW SIDE

PrivateObservation                    ActionClaim
BaselineState                         PublicMintInputs
EvidenceState       EvidencePermit    CapabilityMint
       |                  |                |
       +--------------> ClaimQuotient ----+
```

`ActionClaim` has no public constructor. Production minting accepts `ActionClaim`, pairwise
audience binding, public epoch, and fresh randomness. The synthetic `ActionSemantics` projection
exists only for counterfactual evaluation and carries no authority.

## Counterfactual attack game

The smoke harness creates pairs with different hidden evidence classes and identical action
semantics. Complete sessions, never random windows, are assigned to train, validation, and test.
It compares:

- claim-only attacker
- AETP full-trace attacker
- timing-dependent negative control
- payload-dependent negative control
- retry/failure-dependent negative control

The primary metric is:

```text
excess AUC = AUC(full trace) - AUC(action semantics only)
```

The paired bootstrap resamples counterfactual pair identifiers and reports a 95% interval. The
safe synthetic mechanism uses an exact coupling, so paired worlds receive the same trace under
the same public randomness. Controls deliberately violate one dependency at a time and must be
detected by the same attacker.

## Scope and falsification

This is an implementation smoke, not evidence that a deployed radio/OS stack satisfies AETP.
AETP is falsified for an implementation if any Low Side path accepts private evidence, or if a
full-trace attacker reliably outperforms the action-only attacker on action-equivalent histories.

Retries, clock behavior, logging, serialization, radio scheduling, packet loss, service
collusion, and longitudinal composition must be reevaluated on the real end-to-end system.

## Novelty language

AETP is described as a **candidate new primitive** and a **proposed security notion**. To the best
of our literature review, we found no prior work combining these exact semantics. This is not a
priority, patentability, or exhaustive prior-art conclusion.
