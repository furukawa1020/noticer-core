# QuotientSeal release stack adversarial matrix v1

## Scope

K8-13g4 fixes a deterministic 42-case matrix: 21 scenarios for P0 and the same
21 for P1. These cases mutate public specification receipts. They are
`INJECTED_TEST_FIXTURE` negative controls, not claims of a compiler, engine,
radio, device, or hardware exploit.

## Scenario set

Two canonical cases cover ACTION and COVER. At each of the four handoff
boundaries, RESET, FAULT, and DEADLINE are injected. Seven additional cases
cover receipt replay, duplication, wrong service, wrong policy, stage skip,
stage reorder, and cross-path receipt substitution.

The profile and scenario determine one stable case ID and seed. P0 cases precede
P1 cases, and every profile contains every scenario exactly once.

## Evaluation

Each case records whether the K8-13g2 path verifier accepted the evaluated
artifact, its typed error, the K8-13g3 profile verdict, action/frame/failure
counts, provenance, and a case digest. P0 canonical paths must MATCH. P0
injections must be ATTACK_REJECTED. An injected path that is accepted becomes
INVARIANT_VIOLATION and records any resulting action as unauthorized.

When P1 has no fresh sealed AEPA authorization, all P1 cases remain
PROFILE_UNRESOLVED. They are never counted as MATCH, ATTACK_REJECTED, or an
implicit P0 result. Supplying a valid authorization is supported by the public
API and is bound into the profile artifact used for every case.

## Reproducibility and boundary

Verification checks 42 unique IDs, recomputes every path mutation and profile
decision, reconstructs all counts, and compares the complete matrix artifact.
The fixed seed controls identifiers only; no stochastic search is claimed.

Reference, wasmi, and Wasmtime aggregation is deferred to K8-13g5. Sensor, BLE,
pump, TEE, and physical-device execution remain `NOT_VERIFIED`.
