# QuotientSeal source-target relation validator

## Status

QUOTIENT_SEAL_RELATION_V1 is the versioned K8-05 certificate and independent
checker contract. It is part of a candidate robust-compilation mechanism, not a
general secure compiler or a priority claim.

## Four fail-closed gates

Validation proceeds only after four independent gates:

1. The existing K7-10 translation transcript is VALID.
2. The K7-03 inductive CAQT certificate is independently decoded and VALID.
3. The K8-03 three-parser consensus is VALID and binds the target IR digest.
4. K8-04 executes every target case without trap, termination, or resource
   exhaustion.

Mismatch is INVALID. Unsupported versions are INCOMPATIBLE. Resource exhaustion
is INCONCLUSIVE. Parser disagreement is UNRESOLVED. None becomes VALID.

## Versioned relation certificate

Each reachable source state maps to a canonical target predicate containing an
entry pc set, exit pc set, typed global values, memory byte predicates, and
allowed memory-write ranges. Records and predicates are sorted, unique, and
non-overlapping. The certificate binds the inductive certificate digest, target
IR digest, and K7 manifest digest.

The checker uses an offline-only checker-internals Cargo feature to seed target
globals and memory. That feature is not enabled by the public runtime and does
not add private ingress to the deployed host ABI. Source state is never passed
as a public tick argument.

## Recomputed obligations

For every reachable source state and quotient/public/fault input, the checker
recomputes source transition and target execution. It compares output presence,
payload, actions, next relation, error status, reset, handoff, status, memory
writes, and the complete target observer event trace.

Authorized and recovery actions must occur exactly once in the same step for v1.
Unauthorized and duplicate actions must occur zero times. Every inductive
action-equivalent pair is executed with identical public inputs; trace equality
and successor-pair coupling are checked again after the call.

The first lexicographic divergence is returned with source state, input, pair,
event index, expected value, and actual value so the counterexample is
reproducible.

## Non-goals

This checker does not establish arbitrary-Wasm secure compilation, full
abstraction, JIT/native machine-code correctness, malicious-runtime or
operating-system resistance, or microarchitectural confidentiality. Sensor,
BLE, wearable, and physical hardware behavior remains NOT_VERIFIED.

`VALID`, `INVALID`, `INCOMPATIBLE`, `RESOURCE_BOUND`, and `UNRESOLVED` are distinct
verdicts. Unsupported inputs, exhausted resources, or parser disagreement never become
`VALID`.
