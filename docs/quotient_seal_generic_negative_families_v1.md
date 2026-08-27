# QuotientSeal Generic Negative Families v1

## 目的

8 valid familyへ1対1で対応する8系統の人工negative familyを実装し、generic benchmarkの検出negative controlを固定する。各familyは4 variantを持ち、合計32 caseである。

## Mutation classes

extra host call、private-dependent trap、resource count divergence、exported linear memory、reset state retention、public state corruption、duplicate public action、private handoff carryoverをtyped classとして扱う。各classは最初の差分stepとAPI、control、resource、memory、state、handoffのobserver surfaceを保存する。

negative fixtureはvalid counterpartのfamily IDとsource artifact digestを束縛する。mutated source digestはcounterpart digest、negative family ID、mutation classから決定的に生成する。

## Verdict

全caseの期待判定は`INVALID`である。receiptは最初の差分、action・host call・resource event・trap count、counterpart/mutated digest、seedを完全再計算する。unknown variantとreceipt改ざんはfail-closedで拒否する。

## Claim boundary

すべて`INJECTED_TEST_FIXTURE`であり、実compiler、実runtime、実serviceの脆弱性発見を意味しない。private value、private trace、secret、stable identifierはartifactへ含めない。実hardwareは`NOT_VERIFIED`であり、world-firstを主張しない。

## テスト

```bash
cargo test -p quotient-seal-benchmark --test negative_families
```
