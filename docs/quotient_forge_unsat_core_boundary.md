# QuotientForge Named Assertions and Unsat Core Boundary

## 目的

K7-06dはhard obligationとtyped blockerをcanonical nameへ写し、外部solverが返すunsat coreを非信頼diagnosticとして監査する。coreはbounded `UNSAT`の根拠そのものでも、最小証明でも、candidate受理条件でもない。

## canonical assertion name

nameは次の公開形式だけを許可する。

```text
qf.v1.<namespace>.<8桁ordinal>.<assertion_sha256>
```

namespaceは`security`、`utility`、`fault`、`blocker`の4種である。registryはnamespace、assertion digest、source digestで入力をsortし、namespaceごとにordinalを割り当てる。同じ入力集合は入力順に依存せず同じregistry digestを生成する。nameから元assertionへの復元はdigest推測ではなくregistryの一意lookupだけで行う。

`blocker` namespaceはK7-06cの`SessionBlocker`からのみ構築し、assertion digestとblocker artifact digestを結ぶ。hard obligationがこのnamespaceを直接使用することは禁止する。

## parser境界

受理するcore表現は、canonical nameだけを空白区切りで含む単一のSMT-LIB形式listである。次は再検査前に拒否する。

- 空文字または空list
- 括弧の欠落、nested list、quoted symbol、comment
- canonical grammarに合わないname
- registryに存在しないname
- duplicate name
- solverがcoreを返す契約なのに結果が欠落した状態

raw solver outputはartifactへ保存しない。受理可能なnameだけをcanonical sortした後に保存する。

## 独立再検査

構文とregistry lookupを通過したcoreも、そのままvalid diagnosticにしない。`UnsatCoreRechecker`へ解決済みassertion集合を渡し、再検査が明示的に`UNSAT`を返した場合だけ`validated`とする。再検査が`SAT`または`INCONCLUSIVE`なら`rejected`で停止する。

core非対応solverは`unavailable / unsupported`として明示的にfallbackする。core欠落、空、malformedもdiagnosticを受理しない。一方、これらをbounded `UNSAT`以外のdecisionへ偽装することもない。`bounded_decision`と`diagnostic_status`はartifact上で独立している。

## 非主張

- validated coreをsecurity proofとは呼ばない。
- coreの最小性を主張しない。
- core availabilityによる性能改善を前提にしない。
- coreの有無でcandidate検証やbounded decisionを緩和しない。

## artifact

`quotient_forge_unsat_core_audit_v1.schema.json`はproblem hash、epoch、bounded decision、registry digest、diagnostic status/reason、resolved names、再検査実施有無、diagnostic-only marker、artifact digestを固定する。
