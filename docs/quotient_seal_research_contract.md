# K8 QuotientSeal RAQTR research contract

Status: **FROZEN**  
Contract version: 1  
Freeze date: 2026-08-17  
Parent Issue: #95  
Implementation Issue: #96

## 1. Purpose

This contract freezes the research boundary for QuotientSeal before target-level implementation
or evaluation results are observed. The machine-readable source is
`configs/quotient_seal/k8_research.yaml`; its strict structural schema is
`schemas/k8_raqtr_contract.schema.json`.

QuotientSeal is a candidate robust compilation mechanism and a domain-specific secure
compilation system. The hypothesis is that action-quotient security and hard utility can survive
translation from a CAQT-certified source machine through an untrusted compiler and optimizer to
a restricted WebAssembly module running under an adaptive, capability-scoped host context.

## 2. K7 reuse boundary

K8 does not redefine the K7 action quotient, source certificate, generated runtime manifest, or
one-step cross-target harness. It references the AETP action-equivalence definition and consumes
the K7 CAQT certificate and K7-10 generated runtime once those artifacts are merged.

| Dependency | Required artifact | Frozen status |
|---|---|---|
| K7-02, #76 | bounded AQNI soundness | merged as `9ae3b9819b6fd90abea22c466d3fb7ece16999d0` |
| K7-03, #77 | inductive CAQT certificate | required, not merged at freeze |
| K7-10, #85 | `no_std` / WASM translation validation | required, not merged at freeze |

Until all three dependencies are on `main`, only K8-00 and K8-01 may advance. Copying an
unmerged K7 type, manifest, or certificate into K8 is prohibited.

## 3. Frozen security notion

For a K7 source machine `S`, compiled restricted WASM module `W`, admissible context `C`, and
declared observer projection `pi_o`, RAQTR requires all three obligations below.

1. Robust action-quotient noninterference: action-equivalent private histories produce identical
   declared target-observer traces for every admissible adaptive context.
2. Restricted-context trace refinement: abstracting a target trace yields the source trace under
   the corresponding restricted context abstraction; target-only public behavior is rejected.
3. Utility preservation: authorized action exactly once, public deadlines, zero unauthorized or
   duplicate action, recoverable fault behavior, and fail-closed invalid calls survive translation.

Action equivalence itself remains the definition in `docs/aetp_security_definition.md`. Private
ready time, margin, identity, acquisition path, and baseline may differ only when the referenced
K7 `ActionSemantics` remains equal.

## 4. Adversarial context

The adversary is a capability-scoped language-level reactive machine. It may choose public call
order, public inputs, public faults, reset, handoff, malformed values, repeated calls, public
randomness, and multi-service connections based on prior public observations.

It may not read linear memory directly, acquire the private capability, call a hidden private
function, mutate bytecode during execution, violate engine semantics, read process memory with
root OS authority, or directly observe a microarchitectural cache. A malicious runtime owner is
outside this contract.

The trusted computing base is limited to the K7 source checker, trusted private wrapper,
restricted parser, deterministic target semantics, relational validator, context product checker,
QSM checker, and the eventual Lean preservation theorem. `rustc`, `wasm-opt`, WASM engines,
compiler manifests, Studio, benchmarks, and attack classifiers do not authorize acceptance.

## 5. Observer registry

| ID | Frozen observation |
|---|---|
| `O0_API` | import calls, export returns, public bytes, public error code |
| `O1_TRAP` | return kind, trap kind, termination, bounded nontermination |
| `O2_CONTROL` | branch outcomes, direct calls, loop iterations |
| `O3_INSTRUCTION` | opcode sequence, exact count, histogram |
| `O4_MEMORY` | address, width, read/write kind, page count |
| `O5_SERVICE` | all declared profiles plus service, slot, reset/handoff order |
| `O6_COLLUSION` | combined traces from multiple module instances |

An implementation cannot pass by omitting an observer. Unsupported observation, parser
disagreement, state exhaustion, fuel exhaustion, or engine disagreement is inconclusive rather
than secure.

## 6. Outcome taxonomy

`QSM_VALID` is the only success outcome. Structural RAQTR, refinement, utility, and resource
violations are counterexamples. Timeout, resource bounds, parser/engine disagreement, and missing
tools are inconclusive. Invalid source certificates, unsupported WASM, ABI/relation/capsule
failure, unknown versions, and malformed artifacts are invalid. The four groups are disjoint.

In particular:

- `PARSER_DISAGREEMENT` is never converted to acceptance.
- `ENGINE_DISAGREEMENT` is never averaged away.
- `RESOURCE_BOUND` is not evidence of security.
- compiler success is not QSM validity.
- test execution without independent recomputation is not capsule validation.

## 7. Frozen evaluation gate

The split unit is `module_family`; row-random splitting is prohibited. Train, development, and
held-out families remain separate, including generated variants and compiler configurations.

| Gate | Frozen minimum or maximum |
|---|---:|
| Module families | at least 16 |
| Compiler configurations | at least 12 |
| Binary-level mutants | at least 30 |
| Host context families | at least 12 |
| Engines | at least 2 |
| Explicit call-prefix evaluation | at least 256 |
| Noticer modules | at least 5 |
| Generic valid families | at least 8 |
| Negative families | at least 8 |
| Source-target mismatch | 0 |
| Accepted mutant leak | 0 |
| Held-out mutation detection | 100% |

These are preregistered bounded engineering gates, not universal security constants. Finite
product closure may support an arbitrary-finite-prefix theorem, but an exhausted product bound is
still `RESOURCE_BOUND`.

## 8. Resource and reproducibility contract

The contract fixes named seeds for compiler matrix, mutation, context generation, engine tapes,
attack, performance, split, and capsule generation. Limits cover parser and checker time, memory,
module/capsule bytes, functions, instructions, context/product states, explicit prefix, and fuel.

Every randomized run derives a named child seed and records it. Tool version, binary hash,
compiler command, engine, observer profile, and all resource verdicts belong in the run manifest.
One warmup and five measured repetitions are fixed before performance results.

## 9. Artifact boundary

Generated outputs belong under `artifacts/k8_quotient_seal/` and are not committed. The required
result registry includes the frozen contract, compiler matrix, mutation, cross-engine, robust
context, resource, attack, performance, ablation, invariant, and run-log artifacts.

No artifact may contain raw PPG/ACC, biosignals, baseline values, private history, private margin,
private ready time, participant/device/stable identifiers, key material, token bytes, permit
signatures, or lease bytes. `private_field_count` remains zero.

## 10. Go, Pivot, and Kill

GO requires every `go_all` condition in the machine contract. These include source-target
refinement without mismatch, 100% held-out required-mutant detection, accepted QSM verification,
two-engine agreement, multiple compiler configurations, Noticer and generic modules, detection of
a resource-only leak, and a machine-checked arbitrary-finite-prefix theorem.

Any `pivot_any` condition forces an explicit scope reduction, such as P0 public quotient only,
fuel/import traces instead of exact opcode traces, a custom backend, bounded contexts, or a
reduced Lean semantics.

Any `kill_any` condition kills the full claim. Examples include missing adversarial contexts,
ignoring target-only surfaces, a public private-ingress API, an accepted leaking mutant, trusting
the compiler manifest without parsing the binary, silent unsupported WASM acceptance, utility
failure under a malicious context, or a preservation theorem containing `sorry`.

CI completion alone cannot produce GO.

## 11. Non-claims

K8 does not establish native cycle equality, cache or predictor equality, speculative-execution
safety, power/EM security, JIT machine-code safety, OS scheduling equality, malicious runtime
security, general secure compilation, full abstraction, arbitrary Rust/WASM support, or physical
hardware verification. Native wall-clock timing is empirical evidence only.

The permitted research language is "candidate robust compilation mechanism", "domain-specific
secure compilation system", "proof-carrying AETP compilation capsule", and "action-quotient
translation validation". Priority requires separate literature and patent review.

## 12. Amendment rule

Version 1 is frozen before K8 implementation results. A correction requires a new contract
version, written reason, changed-field list, new canonical fingerprint, preservation of version 1,
and disclosure of whether any result was observed before amendment. Silent edits invalidate the
affected comparison.
