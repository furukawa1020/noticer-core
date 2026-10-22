# Deterministic chaos campaign CLI

7つのdelivery crash pointをseed付きbounded scheduleとして実行し、schedule、最終invariant、完全再生commandをcanonical JSONへ保存する。

```bash
cargo run --manifest-path crates/quotient-commit-core/Cargo.toml --bin quotient-chaos -- --seed 24301 --iterations 32 --maximum-failures 14 --output artifacts/chaos.json
```

- `seed`は0以外、`iterations`は1..10000、failure数はiterations以下に制限する。
- 同一configはbyte-identical artifactを生成する。
- artifactに全failure scheduleを含め、変更されたscheduleのreplayを拒否する。
- artifactは生成物なのでGitへcommitしない。
