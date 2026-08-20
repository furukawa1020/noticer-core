# APLOT QSM Differential Evaluation v1

## 目的

この文書はIssue #179で固定するAPLOT source expectation、QuotientSeal small-step、wasmi、Wasmtimeの差分評価契約を定義する。同一のP0 Wasm、ABI digest、公開command sequence、host tape、resource limitsを全participantへ与える。

source expectationは独立実行器ではない。Issue #178のcanonical compiler placementから、期待されるhost import、output、return、public state、terminationを導出する比較基準である。この制約をartifactのengine identityへ記録する。

## 公開event semantics

fragment attemptは`qseal.emit_frame`を1回生成する。source loss maskでlostと宣言されたattemptは、直後にcode 20993の`qseal.public_failure`を生成する。公開reconnect eventは20994、deadline eventは20995を生成する。

application retry eventは存在しない。`ContextFamily::Retry`は非canonical commandとして拒否する。sourceで宣言されたreconnect eventと、host tapeが注入するreconnect faultは別のaxisであり、同じ意味へ畳み込まない。

## 比較対象

次を順序付きtyped eventとして比較する。

- API callとreturn
- host import名、引数、outcome
- frame attemptとpublic failure output
- resetとhandoff
- public state digest
- termination、trap、resource exhaustion、timeout、engine failure

最初の差分は`ComparisonPoint`として左右eventまたはterminationとaxisを保存する。parser failure、timeout、resource bound、engine failureをMATCHへ格上げしない。

## Verdict

- `MATCH`: source expectationとsmall-stepが一致し、small-step、wasmi、Wasmtimeも一致する
- `COUNTEREXAMPLE`: 実行済みparticipant間にtyped differenceがある
- `UNRESOLVED`: source expectationを構成できない、またはいずれかの実行がparser・timeout・resource・engine境界で未解決

同じ公開入力とengine digestから生成するcanonical JSONはbyte-identicalでなければならない。artifactはsource digest、schedule digest、sequence digest、三engine executable digest、全participant runを束縛する。

## 非主張

- adversarial matrix completeness: `NOT_VERIFIED`
- source-target refinement beyond the declared sequence: `NOT_VERIFIED`
- real BLE controller equivalence: `NOT_VERIFIED`
- radio timing equivalence: `NOT_VERIFIED`
- hardware status: `NOT_VERIFIED`
- 文献・特許上の優先権またはworld-first: 主張しない

このIssueは宣言済みbounded-loss sequenceの差分評価を保存するcandidate mechanismである。loss・duplicate・timeout・capacity・reset・handoffを横断するadversarial bundleはIssue #180で固定する。
