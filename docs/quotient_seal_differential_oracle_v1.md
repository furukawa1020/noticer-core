# QuotientSeal differential oracle v1

## 目的

このoracleは、independent reference semantics、wasmi、Wasmtimeが同一の公開入力に対して生成したobservable artifactを比較する。全engine一致を仮定せず、差分を消去・多数決・曖昧な文字列へ正規化しない。

## reference境界

reference artifactのengine名は`quotient-seal-small-step`とする。oracle自身はreference traceを生成せず、K8-04 small-step semanticsまたは独立したtranslation validation経路が生成したartifactを入力として受け取る。wasmi/Wasmtime artifactを複製してreferenceと呼ぶことは禁止する。

instruction-level traceの規範はreference interpreterだけに置く。native JIT instruction equalityは`NOT_VERIFIED`であり、本oracleの比較対象ではない。

## 入力同一性

共有入力hashはmodule SHA-256、ABI SHA-256、host tape、context sequence、execution limitsをcanonical JSON化して計算する。engine identityは各実行binaryを識別するため異なるので共有hashから除外するが、各`EngineRunArtifact.execution_id_sha256`には引き続き含まれる。

入力不一致、required engine欠落、duplicate engineは比較不能として`UNRESOLVED`にする。

## 判定規則

- `MATCH`: referenceと全engineが`EXECUTED`で、traceとterminationがfield-wiseに一致する。
- `COUNTEREXAMPLE`: 全runが`EXECUTED`だがobservable traceまたはterminationに差がある。
- `UNRESOLVED`: parser disagreement、unsupported feature、resource bound、timeout、engine failure、入力不一致が1つでもある。

`COUNTEREXAMPLE`はengine同士の差を`ENGINE_DISAGREEMENT`、referenceとの差を`REFERENCE_DISAGREEMENT`として別々に保存する。各pairについて最初のtrace indexまたはtermination差だけをminimal counterexampleとし、左右のtyped valueを失わず保存する。

## artifactと再計算

artifactはreference 1件と全engine artifactを内包し、engine identity順へcanonical sortする。`validate`は共有入力hash、verdict、unresolved evidence、counterexampleを独立再計算し、保存値の改変をrejectする。

実機、組込み機器、TEEでの実行は`NOT_VERIFIED`である。本実装はcandidate moduleの研究評価基盤であり、優先権や世界初を断定しない。
