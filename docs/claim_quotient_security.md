# Claim-Quotient Atypicality Token Security Core

The canonical name of the trace property is now **Action-Equivalent Trace Privacy (AETP)**.
See `docs/action_equivalent_trace_privacy.md`. The earlier TNMC name is retained only as research
history; AETP makes the counterfactual action-equivalence relation explicit.

Status: K2 smoke implementation  
Last Updated: 2026-08-09

## Research boundary

Noticer Core does not release a compressed physiological representation. It consumes private
evidence once and irreversibly reduces it to an explicitly authorized consequence:

```text
EvidencePermit -> ClaimQuotient -> ActionClaim -> CapabilityMint -> ObservableTrace
```

The contribution under test is the boundary: after `ActionClaim` is created, private score,
p-value, embedding, baseline, context, evidence epoch, and guarantee marker are unavailable to
the Low Side API.

## Type-enforced dependency rule

`noticer-claim` is the only production crate that accepts `EvidencePermit`. Its
`ClaimQuotient::declassify` operation consumes the non-cloneable permit and validates the public
policy hash, action allow-list, and lifetime. `ActionClaim` has no public constructor.

`noticer-release` depends on `noticer-claim`, `noticer-protocol`, and public primitive types. It
does not depend on `noticer-evidence` or `noticer-baseline`. `CapabilityMint::mint` accepts only:

- `ActionClaim`
- pairwise audience binding
- public key epoch
- fresh public randomness

## TNMC smoke game

For private histories `H` and `H'` with the same allowed claim sequence `C`, the target is:

```text
R(H; C, P, U) == R(H'; C, P, U)
```

for the same public policy `P` and coupled public randomness `U`. The K2 smoke game compares the
complete encoded packet bytes, logical timing, packet count, and packet size for both worlds.
Private histories are deliberately absent from the simulator API.

This exact coupled equality is an implementation dependency test, not a scientific privacy
result. It does not establish distributional privacy against real transport, OS, radio, or
adaptive attackers. K4 and K5 must separately test timing, loss, retries, collusion, and learned
distinguishers.

## Allowed and excess leakage

The evaluation must report these separately:

```text
L_allowed = Leakage(S; C)
L_excess  = Leakage(S; R | C)
```

TNMC constrains `L_excess`; it does not claim that publishing `C` is inherently privacy-safe.

## Falsification

K2 fails if any of the following occurs:

- a Low Side mint or trace API accepts score, p-value, embedding, baseline, or private context
- two matched-claim worlds differ under the same public policy and coupled randomness
- packet timing or size depends on hidden evidence rather than the public schedule
- an error path serializes or logs private evidence
- an `ActionClaim` can be constructed without consuming an authorized permit
