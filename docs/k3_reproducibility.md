# K3 reproducibility and artifacts

## Toolchain

- Rust workspace, stable toolchain, CPU only.
- Python package from the repository `src/` layout.
- Python dependencies declared in `pyproject.toml`.
- Randomness controlled by `configs/token/k3_demo.toml` and evaluator CLI seed.
- Paths are supplied with `pathlib.Path` in Python and `PathBuf` in Rust.

## Commands

Run implementation checks:

```text
cargo check --workspace
cargo test --workspace
python -m pytest
python -m ruff check .
```

Generate K3 evidence:

```text
cargo run --release -p noticer-token-demo -- --config configs/token/k3_demo.toml --output artifacts/k3_token_v2
python -m noticer_core.evaluation.token_attacks --witnesses artifacts/k3_token_v2/counterfactual_witnesses.csv --output artifacts/k3_token_v2
```

## Artifact contract

| File | Meaning |
|---|---|
| `manifest.json` | version, dimensions, cache semantics, and non-persistence declarations |
| `admission_bridge.json` | two real K1 permits reduced to one public plan and equal ATv2 traces |
| `counterfactual_witnesses.csv` | one sanitized row per private pair |
| `full_trace_classes.csv` | full-crypto byte-equality witness per public equivalence class |
| `verifier_checks.json` | acceptance, mutation, replay, binding, expiry, revocation, race, and restore checks |
| `performance.csv` | median, p95, and p99 cover-token issuance time |
| `token_attack_dataset.parquet` | paired public trace features only |
| `token_attack_results.csv` | model-cell metrics and pair-bootstrap intervals |
| `longitudinal_results.csv` | mechanism/view/horizon aggregate |
| `token_attack_summary.svg` | observer-view summary figure |

## Excluded data

Artifacts must not contain biosignal samples, baseline values, score paths,
evidence-ready time, evidence expiry, subject/session secrets, root secrets,
derived signing or AEAD keys, nonces outside public envelopes, or private permit
provenance. The artifact directory is ignored except for its explanatory
README.

## Determinism caveat

Witness generation, scheduling, splits, and feature controls are deterministic
for a seed. Wall-clock benchmark values and floating-point model output may vary
slightly across CPUs and library builds; thresholds should account for that.
