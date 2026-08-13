# K3 counterfactual trace attack evaluation

## Purpose

This is an implementation and falsification harness, not a physiological study
and not evidence of clinical utility. Synthetic private histories are generated
only to ask whether different histories with equal action semantics leave a
distinguishable token trace.

## Counterfactual pairs

The Rust generator creates 10,000 pairs across six families:

- early versus late private evidence readiness;
- smooth versus spiky private score path;
- different personal baseline;
- different noise path;
- different subject;
- different session.

Private fields stay inside `noticer-aetp-sim`. Artifacts retain only pair ID,
family, public equivalence-class ID, boolean private-distinct witness, boolean
trace-equality witness, and trace SHA-256.

## Full-token congruence

Each equivalence class executes two independent `TokenIssuer` states initialized
with equivalent root bytes, the same public context, and the same schedule tape.
The harness compares every byte of all 1,024 frames produced by 64 buckets,
four slots per bucket, and four services. Frame issuance still performs HKDF,
Ed25519, XChaCha20-Poly1305, and nonce-use checks.

Pairs sharing an identical public plan and schedule tape use the same cached
full-crypto class witness. This is an explicit equivalence-class optimization,
not a claim that 10,000 separate encryptions were run. Every private pair is
still generated, checked for distinctness, and assigned a sanitized witness.

## Attack dataset

Python builds paired public-trace features for ATv2 and five intentionally
broken controls:

| Mechanism | Deliberate leak |
|---|---|
| `ReadySlotToken` | release offset follows private readiness |
| `ScoreBucketToken` | score bucket is released |
| `VariableLengthToken` | length and byte count vary |
| `PerActionOnlyToken` | frame count reveals action occurrence |
| `SharedServiceIdentifierToken` | cross-service linkable identifier |
| `ATv2` | paired features remain exactly equal |

The observations are evaluated at 1, 4, 16, and 64 public buckets for full
observer, single-service, and colluding-service views. Logistic regression,
depth-limited decision tree, Gaussian naive Bayes, and linear discriminant
analysis report balanced accuracy and ROC AUC. Pair IDs, not rows or frames,
are split between train and test. Bootstrap intervals resample whole pairs.

## Interpretation

Broken controls should be learnable and ATv2 should remain near chance. A
chance result is not proof of privacy; it is evidence only against the listed
attacks and features. Exact coupled trace equality is a stronger implementation
witness for the generated equivalence classes but remains short of a universal
proof over all programs and deployments.

## Reproduction

Windows:

```powershell
./scripts/run_k3_token_v2.ps1
```

Linux:

```sh
./scripts/run_k3_token_v2.sh
```

Generated files under `artifacts/k3_token_v2/` are ignored by Git.
