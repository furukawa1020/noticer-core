# QuotientSeal Generic Benchmark Reproduction v1

## 目的

generic registry、8 valid family、8 negative family、family-disjoint split、64-case baseline/full比較を単一のcanonical JSON bundleへ固定する。保存済みdigestやsummaryだけを信用せず、master seedとtyped入力から全段階を再生成する。

## 完全再計算

master seedからregistry seedとsplit seedをdomain別tagで導出する。registryからvalid fixturesを再生成し、そのcounterpartからnegative fixturesを再生成する。splitを再生成した後、64 caseのcomparisonとgate summaryを再評価する。いずれかが保存値と異なればfail-closedで拒否する。

component digestはsource tree、config、registry、valid 8件、negative 8件、split、comparisonを個別に束縛する。external expected inputsを使う`verify_complete_recomputation`は、攻撃者がbundle内部を一貫して作り直した場合も期待実験と区別する。

## 再現

```bash
cargo run -p quotient-seal-benchmark --example generic_benchmark_reproduction -- --output artifacts/generic_benchmark
```

`generic_benchmark_bundle.json`と`generic_benchmark_summary.json`を生成する。生成artifactはGitへcommitしない。

## Claim boundary

この再現commandは`INJECTED_TEST_FIXTURE`のschema・split・oracle harnessを検査する。wasmi、Wasmtime、実compiler、実Noticerを評価したartifactではなく、toy successはNoticer claimを代替しない。private value、private trace、secret、stable identifierを含めない。実hardwareは`NOT_VERIFIED`であり、world-firstを主張しない。

## テスト

```bash
cargo test -p quotient-seal-benchmark --test reproduction
```
