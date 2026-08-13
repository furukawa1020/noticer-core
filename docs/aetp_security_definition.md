# Action-Equivalent Trace Privacy (AETP)

## Status and scope

Action-Equivalent Trace Privacy is a **proposed security notion** and a
**candidate new primitive** for release systems driven by private biosignals.
To the best of our literature review, we found no prior work combining these
exact semantics: private evidence admission, explicit action equivalence,
fixed-schedule encrypted token traces, pairwise service binding, and one-shot
authorization. This statement is not a priority or world-first claim.

AETP is the central research contribution. Atypicality Token v2 (ATv2) is one
protocol construction intended to realize it.

## Notation

Let `H` be a private history containing biosignals, personal baselines,
intermediate scores, evidence-ready time, and evidence provenance. Let `C` be
public context: services, epoch, bucket schedule, frame cadence, and public
policy. Let `A(H, C)` be the admitted action semantics after the private
evidence gate. Let `R(H, C; rho_s, rho_c)` be the entire observable release
trace under schedule randomness `rho_s` and cryptographic randomness/state
`rho_c`.

Two histories are action-equivalent under context `C` when:

```text
H0 ~=_A,C H1  iff  A(H0, C) = A(H1, C)
```

The equality covers service, action, public bucket, admission cutoff, release
window, deadline, maximum use count, policy hash, and authorized claim bound.
It deliberately does not expose evidence-ready time or evidence score.

## Coupled trace definition

A construction satisfies exact coupled AETP for an equivalence class when,
for every `H0 ~=_A,C H1`, using the same public schedule tape and equivalent
cryptographic initial state gives:

```text
R(H0, C; rho_s, rho_c) = R(H1, C; rho_s, rho_c)
```

Equality includes packet count, timing slots, service-local ordering, length,
outer metadata, ciphertext, cover/action placement, and the full longitudinal
byte stream. Coupling is an executable non-interference witness, not by itself
a universal cryptographic proof.

For ordinary independently randomized executions, the target notion is
computational indistinguishability of the two induced trace distributions.
The paired attack evaluation estimates whether selected adversaries can
distinguish those distributions over several horizons and observation views.

## Observers and views

- `observer`: sees the complete public transport trace.
- `single_service`: sees one pairwise service view.
- `colluding_services`: combines multiple service views but has no root key.
- verifier: receives its service/epoch key material and can authorize only its
  bound service.

## Security goals

- No private evidence time, score, baseline, subject identity, or session
  identity is representable below admission.
- Action-equivalent histories produce the same scheduled frame positions.
- Every frame is exactly 236 bytes, whether cover or action.
- Service and epoch keys are domain-separated.
- A valid action token authorizes exactly one permitted action.
- Replay acceptance is atomic across concurrent verifier calls.
- External rejection behavior is normalized to avoid a detailed error oracle.

## Non-goals

- Hiding action semantics that the application is explicitly authorized to
  perform.
- Protecting a compromised endpoint that observes private evidence before
  admission.
- Availability against jamming or packet deletion.
- Claiming differential privacy, Pufferfish privacy, anonymity, or unlinkability
  beyond the defined service/epoch scope.
- Establishing novelty priority without additional literature and patent work.

## Falsification conditions

AETP is falsified for this construction if any action-equivalent pair reveals a
different frame count, slot, length, service-visible identifier, or byte trace
under the coupled witness; if a low-side public type carries private evidence
timing; if an attacker reliably exceeds its preregistered chance threshold on
ATv2 while controls remain learnable; or if replay races authorize more than
one action.
