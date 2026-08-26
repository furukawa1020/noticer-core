# Release Stack 再現 Bundle v1

## 目的

composition契約、canonical path、profile gate、adversarial matrix、三系統differential oracleを単一のcanonical JSONへ束縛する。保存済みsummaryを信用せず、外部入力からbundleを再構築してbyte単位で比較する。

## 束縛する入力

- source tree digestと一元seed
- config、composition、path、profile、matrix、differential artifactのdigest
- AETS、ATv2 Frame Planner、APLOT、AEPA、Menfugu Execution Plannerのmodule artifact digest
- 各moduleに対するreference small-step、wasmi、Wasmtime artifact digest
- 各caseのprofile、verdict、action・frame・failure count、最初の差分、evidence origin

composition、path、profile、differentialのcomponent digestは、内包するdifferential artifactのbindingと一致しなければならない。case IDは昇順かつ一意でなければならない。欠測、順序違反、digest不一致、count overflow、verdictとreceiptの不整合はfail-closedとする。

## 完全再計算

`verify_internal_recomputation`はbundle内部の自己整合性を検査する。`verify_complete_recomputation`は、独立に与えた期待入力からbundleを再生成し、canonical JSONをbyte比較する。攻撃者が内包engine digestとbundle digestを同時に作り直しても、期待入力が不変なら不一致になる。

summaryのcase count、各verdict count、action・frame・failure総数、最初の差分、stack verdictはcase receiptとdifferential verdictから再集計する。

## 再現コマンド

```bash
cargo run -p quotient-seal-noticer --example release_stack_reproduction -- --output artifacts/release_stack
```

出力は`release_stack_bundle.json`と`release_stack_summary.json`である。これはschemaとharnessの決定性を確認する`INJECTED_TEST_FIXTURE`であり、生成物はGitへcommitしない。

## K7 one-stepとの差分

K7は個別QSMのone-step refinementを検査する。K8-13g6はその結果を再実行する代替物ではなく、5 moduleのhandoff、profile、攻撃行列、三engine evidenceをstack単位でcross-bindし、同じ入力から同じbundleを再生成できることを検査する。

private ingress capability、biosignal、subject identifier、raw witnessはartifactへ収録しない。実sensor、BLE、Polar Verity Sense、pump、TEEは`NOT_VERIFIED`である。world-firstを主張しない。

## テスト

```bash
cargo test -p quotient-seal-noticer --test release_stack_reproduction
```
