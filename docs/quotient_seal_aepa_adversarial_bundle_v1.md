# AEPA Adversarial Bundle v1

## 目的

この文書はIssue #189で固定するAEPA adversarial matrixとcounterexample bundleを定義する。normal、replay、expiry、downgrade、wrong binding、duplicate、target-only admission、fuel boundary、host-call boundaryの9シナリオを、P0 Public Quotient OnlyとP1 Sealed Admissionの両方で評価する。

matrixは32 byte seed、source digest、36遷移digest、profile、scenario、public sequence、resource limitsからcase IDを決定する。同じ入力からmatrix bytes、execution artifact、counterexample bundleをbyte-identicalに再計算できなければ受理しない。

## Profile gate

P0ケースは既存P0 manifest bindingを通過してから実行する。P1ケースはIssue #190のfresh resource revalidationとP1 manifest evidenceを通過してから実行する。profile名だけを付け替えた実行結果はP1 evidenceではない。

## Faultとresourceの分離

replay、expiry、downgrade、wrong binding、duplicateはpublic commandとAEPA transitionに基づくtyped scenarioである。fuelまたはhost-call上限による停止はresource exhaustionであり、fault成功またはcounterexampleへ読み替えない。resource exhaustionはUNRESOLVEDである。

target-only admissionは、正常な実行結果を科学的観測として改変するものではない。Wasmtime participantだけへaction eventを挿入した`INJECTED_TEST_FIXTURE`として生成し、oracleがCOUNTEREXAMPLEを検出できることだけを確認する。

## Counterexample bundle

counterexampleはoriginal input、minimized input、最初のtyped difference、matrix digest、case ID、全shrink attemptを束縛する。縮約順序は固定し、同じtyped differenceを保つ候補だけを採用する。保存済みbundleは入力から全体を再実行し、canonical JSONまで一致する場合だけ有効とする。

## 非主張

本bundleはsoftware上の再現可能なadversarial test artifactであり、注入反例は科学的実験結果ではない。実端末、Polar Verity Sense、Android、hardware-backed key、実radio、実CPUは`NOT_VERIFIED`である。

この成果物は候補primitiveの評価基盤であり、world-firstや文献・特許上の優先権を主張しない。
