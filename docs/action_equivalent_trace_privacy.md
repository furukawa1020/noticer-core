# Action-Equivalent Trace Privacy (AETP)

Status: proposed security notion and K2 executable specification  
Last Updated: 2026-08-12

## Definition

Let `H` be a private biosignal history, `P` a public admission policy, `C` public context,
and `Phi_P(H, C)` the authorized action semantics. Define:

```text
H0 equivalent_A H1
iff Phi_P(H0, C) = Phi_P(H1, C)
and C is identical
and the obligations are jointly feasible on the public schedule.
```

Action/no-action, different action codes, different public buckets, and different deadlines are
not action-equivalent. The action semantics are intentional declassification.

A mechanism satisfies AETP when complete observable release traces are indistinguishable for
action-equivalent histories. The trace includes ciphertext, packet length, timing, packet count,
silence, public delivery/drop status, action placement, pairwise service aliases, public failure,
cross-service relationships, and repeated buckets.

## Objects

`PrivateHistory` contains synthetic evidence trajectory, permit readiness, hidden identity,
private context, and confidence. It has no public fields, serialization implementation, or
private-value `Debug` output. The trace shaper crate does not depend on its crate.

`ActionSemantics` contains only service, registered action, public bucket, admission cutoff,
release window, deadline, max uses, and policy hash. Exact private permit time, score, p-value,
e-value, confidence, baseline, identity, physiological feature, semantic diagnosis, and private
context are forbidden.

`PublicContext` contains protocol version, epoch, predetermined channel schedule, and a public
network tape. It must be identical in both worlds.

## Security game

1. The adversary chooses `H0`, `H1`, public context, and auxiliary information.
2. The challenger verifies `H0 equivalent_A H1`.
3. The challenger samples `b` uniformly from `{0, 1}`.
4. It computes `R = M(Hb, C; r, n)`.
5. It gives `R`, action semantics, public context, and auxiliary information to the adversary.
6. The adversary outputs `b_prime`.

```text
Adv_AETP(A) = |Pr[b_prime = b] - 1/2|
```

Computational AETP requires this advantage to be at most a declared bound for every efficient
adversary in the stated threat model.

## Statistical variant

For every action-equivalent pair and observable event `O`, both directions must satisfy:

```text
Pr[M(H0) in O] <= exp(epsilon) Pr[M(H1) in O] + delta
```

The optional `ApproximateAetpBudget` provides basic additive accounting. It is not the K2 central
contribution and is not presented as a new general privacy framework.

## Pointwise AETP

K2 targets the stronger executable property:

```text
H0 equivalent_A H1 implies M(H0; r, n) = M(H1; r, n)
```

for the same scheduler/encryption random tape `r` and public network tape `n`.
`CoupledTraceWitness` records semantics and trace hashes and requires byte, service-view, and
collusion-view equality. This is an executable implementation witness, not a mathematical proof
of all deployed components.

## Longitudinal composition

If every bucket transition depends only on action semantics, public state, domain-separated
randomness, and the public network tape, concatenation preserves pointwise equality. K2 executes
this check for 64 buckets and four services. Any future adaptive omission, batching, suppression,
or secret-dependent state invalidates this structural argument and requires approximate analysis.

## Leakage accounting

```text
allowed leakage = Leakage(S; ActionSemantics)
excess leakage  = Leakage(S; ObservableTrace | ActionSemantics)
```

Conditional Excess Trace Advantage is an evaluation metric, not the AETP primitive itself.

## Non-goals

- hiding action presence, action code, public bucket, or public deadline
- hiding public packet loss or public network state
- bystander inference from the visible physical action
- endpoint compromise, malicious sensor firmware, or raw biosignal access
- K1 baseline poisoning
- replay, forgery, revocation, token theft, remote attestation, or TEE security
- differential privacy of raw PPG or unconditional privacy under arbitrary auxiliary information

## Research positioning

AETP is a **candidate new primitive** and **proposed security notion**. To the best of our
literature review, we found no prior work combining these exact semantics. This statement is not
an exhaustive literature, patentability, or priority conclusion.
