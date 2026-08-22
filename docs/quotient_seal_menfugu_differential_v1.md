# Menfugu QSM differential evaluation v1

## 目的

Issue #199では、Menfugu source reference、QuotientSeal small-step、wasmi、Wasmtimeを同じpublic sequenceとhost tapeで実行し、完全な公開観測traceを比較する。compilerが生成したWasmを複数engineで動かすことで、source-to-target refinementとengine間一致を分離して記録する。

これは提案中のsecurity notionを支える評価基盤であり、world-firstを断定しない。実機状態は`NOT_VERIFIED`である。

## 比較する4観測

| Path | 役割 |
|---|---|
| source reference | 56遷移表から期待traceを導出する |
| small-step | canonical target IRを検査器semanticsで実行する |
| wasmi | 生成Wasmを独立engineで実行する |
| Wasmtime | 生成Wasmを別実装で実行する |

三系統engineという呼称ではsource referenceをoracle側に置き、実行engineはsmall-step、wasmi、Wasmtimeの3つを指す。

## Complete observable trace

比較対象はAPI call/return、host import、frame、action、public failure、reset、handoff、公開state digest、terminationである。最初に異なるevent indexとaxisをtyped `ComparisonPoint`として保存する。

public sequence digestはsource、transition、module、capsule、ABI、全command、host tape、fuel、memory、host-call、timeout上限へcommitする。各engine identityには実行binaryのSHA-256を必須とする。

## 三値oracle

- `MATCH`: source refinementと全実行engineが一致した
- `COUNTEREXAMPLE`: resource上限では説明できないtyped differenceが存在した
- `UNRESOLVED`: fuel、memory、host-call、timeout、unsupported featureなどで結論できない

resource exhaustionを成功として扱わない。source側が必要host call数を上限内で実行できない場合も`UNRESOLVED`にする。

## 注入negative control

target-only action、extra host call、target-only trapは差分検出器を壊していないことを確認する人工fixtureである。artifactへ`INJECTED_TEST_FIXTURE`とcanonical labelを必須で記録し、実際のcompiler counterexampleや科学的結果として表示することを禁止する。

## Privacy boundary

評価入力は公開command、公開host outcome、固定resource limitだけである。token ID、replay集合、raw biosignal、private baseline、private evidenceはsequence、trace、artifactへ入れない。

## 次の境界

本Issueは代表sequenceのcross-engine一致を固定する。seeded adversarial matrixはIssue #200、実行由来counterexampleの最小化とbundle化はIssue #201で扱う。物理pump、BLE、Polar Verity Senseは引き続き`NOT_VERIFIED`である。
