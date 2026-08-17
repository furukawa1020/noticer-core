# Bounded AQNI Checker Soundness in Lean 4

## Status

K7-02は、有限AQRS modelに対するbad-state checkerの数学的核をLean 4で機械検証する。toolchainは`leanprover/lean4:v4.30.0`へ固定し、MathlibやRust/Python実装へ依存しない。

## Formal boundary

[`Model.lean`](../formal/aqrs/AQRS/Model.lean)は次の有限domainを明示する。

- plant state、private history、total transition
- shared environment input、そのpublic symbolとfault
- action semanticとauthorized obligation
- recoverable fault obligation
- release、observer projection、action emission

中心定理`AQRS.boundedCheckerSound`は、horizonと全domainの完全な有限列挙`FiniteDomains`をstatementに持つ。同じinput traceを受けるaction-equivalentかつ`PrivateDistinct`な2 runについて、horizon未満のreachable product stateにbad stateが存在しないなら、次を導く。

- 全declared observerでrelease observationが一致する
- unauthorized actionがない
- 同じobligation referenceの重複actionがない
- authorized deadlineまでにexactly onceでactionが生じる
- recoverable fault deadlineまでにexactly onceでrecovery actionが生じる

`AQRS.QuotientAdmissible.not_related_of_semantic_ne`は、action semanticsが異なるstate対をadmissible quotient relationがmergeできないことを示す。

## Negative witness

[`Negative.lean`](../formal/aqrs/AQRS/Negative.lean)はslot 0で必須actionを持つ1-state modelと、actionを一切出さないsuppress-all release machineを定義する。次を機械検証する。

- suppress-allはdeadline violationを持つ
- suppress-allは`UtilitySafeThrough`を満たさない
- suppress-allにはreachable bad stateが存在する

したがって、observer traceを沈黙させるだけでは中心定理のutility側を通過できない。

## Reproduction

```bash
cd formal/aqrs
lake build
lake env lean AQRS/Audit.lean
```

CIでは公式`lean-action`と`actions/checkout`をcommit SHAへ固定する。通常のLean kernel buildに加え、`leanchecker`とRust製external checker`nanoda`を実行し、`nanoda-allow-sorry: false`を指定する。source guardは`sorry`、追加の論理公理宣言、`opaque`、`unsafe`を拒否する。

生成される`.lake/`はGitへcommitしない。

## Non-claims

- infinite trace soundnessは証明しない。
- Rust/Python frontendからLean modelへのlowering correctnessは証明しない。
- physical BLE/network observationがmodelと完全一致することは証明しない。
- wall-clock、memory、solver実装の正しさは証明しない。
- theoremはfinite abstractionと明示horizonの外へ一般化しない。
- 新規性、優先権、world-firstを主張しない。
