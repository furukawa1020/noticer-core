# Bounded AQNI Checker Soundness in Lean 4

## Status

K7-02は、有限AQRS modelに対するbad-state checkerの数学的核をLean 4で機械検証する。toolchainは`leanprover/lean4:v4.30.0`へ固定し、MathlibやRust/Python実装へ依存しない。

## Formal boundary

[`Model.lean`](../formal/aqrs/Aqrs/Model.lean)は次の有限domainを明示する。

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

[`Negative.lean`](../formal/aqrs/Aqrs/Negative.lean)はslot 0で必須actionを持つ1-state modelと、actionを一切出さないsuppress-all release machineを定義する。次を機械検証する。

- suppress-allはdeadline violationを持つ
- suppress-allは`UtilitySafeThrough`を満たさない
- suppress-allにはreachable bad stateが存在する

したがって、observer traceを沈黙させるだけでは中心定理のutility側を通過できない。

## Reproduction

```bash
cd formal/aqrs
lake build
lake env lean Aqrs/Audit.lean
```

CIでは公式`lean-action`と`actions/checkout`をcommit SHAへ固定する。通常のLean kernel buildに加え、bundled `leanchecker`で生成済みoleanを再検証する。source guardは`sorry`、追加の論理公理宣言、`opaque`、`unsafe`を拒否する。

Rust製external checker `nanoda` v0.4.17はsource revision `4c544ed4099c8227f07d5de77ad1e69fb0740a27`へ固定する。Lean 4.30のAQRS exportを完走し、未許可公理を実際に使用するfixtureとmalformed NDJSONを拒否するblocking CIとして運用する。environment再構成用の標準4公理と、AQRS theoremごとの公理依存監査は分離し、後者は`propext`だけを許可する。

生成される`.lake/`はGitへcommitしない。

## Non-claims

- infinite trace soundnessは証明しない。
- Rust/Python frontendからLean modelへのlowering correctnessは証明しない。
- physical BLE/network observationがmodelと完全一致することは証明しない。
- wall-clock、memory、solver実装の正しさは証明しない。
- theoremはfinite abstractionと明示horizonの外へ一般化しない。
- 新規性、優先権、world-firstを主張しない。
