# QuotientSeal adversarial context product checker

Status: **FROZEN v1**

This document defines the K8-06 finite-product checker. It is a candidate
robust-compilation mechanism built on the frozen K8-01 semantics and the K8-05
source-target relation validator.

## Security statement

For every declared private-distinct K7 `RelationPair`, every frozen observer
profile O0-O6, and every one of the twelve finite context families, the checker
couples the left and right worlds with the same context state, public command,
and public randomness. It explores the reachable product with canonical BFS.

An `ACCEPT` result requires all of the following:

- the K8-05 relation verdict is `VALID`;
- relation, inductive-certificate, and target-IR digests match the step oracle;
- all twelve context families are finite, deterministic, canonical, and total;
- every reachable product state reaches a visited fixpoint within configured bounds;
- source traces, observer projections, utility, and relation witnesses agree;
- all seven finite-product induction obligations are present.

Finite closure plus base case, step closure, source/target/context determinism,
finite state space, and resource progress is the explicit guard used to lift the
checked graph from finite BFS paths to arbitrary finite call prefixes. This is a
machine-checkable guard, not the K8-09 mechanized preservation theorem.

## Context families

The frozen families are `TICK`, `RESET`, `HANDOFF`, `MALFORMED`, `RETRY`,
`DEADLINE`, three public fault classes, `SERVICE_COLLUSION`,
`CROSS_SERVICE_REPLAY`, and `STOP`. No command variant can encode private ingest,
private-history reads, private-state reads, or linear-memory reads.

## Counterexamples

The predecessor graph reconstructs the shortest call sequence. Canonical queue,
family, pair, observation, and randomness order break ties reproducibly. The
`QSCP` artifact records the observer, family, private pair, shared command,
shared emitted action, first divergence, and both public observations. It never
contains biosignal samples or private histories.

## Fail-closed outcomes

Prefix exhaustion, product-state exhaustion, unknown context observations,
unsupported execution, parser disagreement, resource exhaustion, missing
induction obligations, and relation-binding mismatch are `INCONCLUSIVE`; none is
converted to `ACCEPT`. A known source, target, relation, utility, boundary, or
observer divergence is a `COUNTEREXAMPLE`.

The hard maximum checked prefix is 256 calls. Smaller configured limits are
allowed and remain explicit in an inconclusive verdict.

## Trust and non-claims

The `ValidatedProductSystem` implementation is part of the checker TCB until the
K8-08 independent QSM checker binds its transition table. K8-06 does not reparse
Wasm or replace K8-03, K8-04, or K8-05.

This work does not establish arbitrary-Wasm secure compilation, full
abstraction, JIT/native-code correctness, malicious runtime or OS resistance,
or microarchitectural confidentiality. Sensor, BLE, wearable, and physical
hardware behavior remains `NOT_VERIFIED`.
