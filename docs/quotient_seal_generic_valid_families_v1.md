# QuotientSeal Generic Valid Families v1

## 目的

generic benchmark contract上へ8系統のvalid source fixtureを実装する。各familyは4 variantを持ち、同じregistry seedからbyte単位で再生成できる。

## Source semantics

source programはprivate predicate評価、allowed action semanticsへの射影、constant-rate public slot、public reset、public handoffの5操作で構成する。synthetic private historyのbucket値は実行時入力にのみ存在し、fixture、receipt、digest inputへ保存しない。

同じvariantに対してprivate historyが異なっても、allowed action semanticsが同じならpublic trace、count、final public state、receipt digestは一致する。allowed action semanticsが異なる比較はaction-equivalent比較ではないため拒否する。

## Public receipt

各receiptはtick、decision slot、actionまたはcover、reset acknowledgement、handoff acknowledgementの5 eventを持つ。action count、reset count、handoff count、source artifact digest、seedを完全再計算する。

## Claim boundary

全familyは`INJECTED_TEST_FIXTURE`であり、実service、実compiler、Noticer、実biosignalでのsecurity結果ではない。toy successはNoticer統合の実証を代替しない。実hardwareは`NOT_VERIFIED`であり、world-firstを主張しない。

## テスト

```bash
cargo test -p quotient-seal-benchmark --test valid_families
```
