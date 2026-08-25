# Menfugu target-only counterexample bundle v1

## 目的

Issue #201では、Menfugu QSMで検出したtarget-only action、extra host call、trapを、元入力と最小入力を含む再現可能なcounterexample bundleへ固定する。

本bundleは差分検出器とshrinkerの動作を確認する人工negative controlである。実compilerの脆弱性や科学的counterexampleとして扱わず、world-firstを断定しない。物理pump、BLE、Polar Verity Senseは`NOT_VERIFIED`である。

## Source case

基準は#200 matrixの`P0_PUBLIC_QUOTIENT_ONLY / COVER` caseである。source semanticsはframeを出すがactionを許可しないため、target側だけに現れるactionを曖昧なく分類できる。

original入力は`cover + stop`、最小化候補は`cover`である。case IDによりmatrix、source、compiled module、capsule、public sequenceへ束縛される。

## Typed injections

| Injection | 期待difference |
|---|---|
| target-only action | trace output axisに余分なactionが現れる |
| extra host call | host-import axisに余分なcallが現れる |
| target-only trap | termination axisがtrapへ変わる |

各injectionは`INJECTED_TEST_FIXTURE`と専用labelをartifactへ保存する。注入結果を実行由来の研究結果として表示することは禁止する。

## Deterministic shrink

shrink順序は次の2操作で固定する。

1. trailing `stop`を除去する
2. primary `cover` stimulusを除去する

候補は同じdifference origin、engine、typed axisを維持した場合だけ採用する。別difference、`UNRESOLVED`、evaluation errorはそれぞれ拒否理由としてattempt logへ残し、最小反例として採用しない。

## Bundle binding

bundleはmatrix digest、case ID、source/transition/module/capsule digest、original/minimized input digest、両実行result digest、first typed difference、全shrink attemptを含む。検証時は入力生成、engine実行、注入、oracle、shrink、canonical JSONを最初から再計算し、1 byteの差も拒否する。

## Privacy boundary

入力とbundleは公開command、公開resource limit、observable traceだけを保持する。token ID、replay集合、raw PPG、raw biosignal、private baseline、private evidenceは保存しない。

## 検証境界

本Issueで確認するのはsoftware-onlyの注入negative controlである。実端末、物理pump、BLE、Polar Verity Sense、実環境counterexampleはすべて`NOT_VERIFIED`である。
