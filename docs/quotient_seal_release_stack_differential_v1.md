# Release Stack 三系統 Differential Oracle v1

## 目的

5つのQSM moduleが生成した既存differential artifactを、release stack単位の三値判定へ集約する。下位のreference small-step、wasmi、Wasmtime実行器を置き換えるものではない。各module artifactのdigestと三実行系のartifact digestを正規化し、stack全体で再計算可能な証拠を作る。

## 判定規則

canonical stage順はAETS、ATv2 Frame Planner、APLOT、AEPA、Menfugu Execution Plannerで固定する。

- 1件以上の`COUNTEREXAMPLE`があればstack判定は`COUNTEREXAMPLE`
- counterexampleがなく1件以上の`UNRESOLVED`があれば`UNRESOLVED`
- 5 moduleすべてが`MATCH`の場合だけ`MATCH`
- 最初のcounterexample stageと最初のunresolved stageを別々に保存する

counterexampleを欠測や多数決によって`MATCH`へ丸めない。

## Binding

artifactはmanifest、composition contract、canonical path contract、profile contractのSHA-256を束縛する。各module evidenceは、元module differential artifactとreference、wasmi、Wasmtimeの三実行artifactをそれぞれSHA-256で束縛する。canonical encodingからstack artifact digestを再計算する。

## Evidence boundary

`EXECUTED_SOFTWARE`と`INJECTED_TEST_FIXTURE`を区別する。fixture由来のcounterexampleはoracle negative controlであり、実compiler、実engine、実deviceの脆弱性を意味しない。private ingress capability、biosignal、subject identifier、raw witnessはartifactへ収録しない。

実sensor、BLE、Polar Verity Sense、pump、TEEでの検証は`NOT_VERIFIED`である。

## 再現

```bash
cargo test -p quotient-seal-noticer --test release_stack_differential
```

この実装はcandidate research mechanismの検証基盤であり、`world-first`を主張しない。
