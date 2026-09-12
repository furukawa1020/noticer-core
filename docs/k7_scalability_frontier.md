# K7 scalability frontier v1

## 目的

K7-09fは測定済みrunだけから、各backendのcompleted最大modelと未完了最小modelを決定論的に算出する。欠測を成功または失敗へ補間せず、失敗原因と非単調性を隠さない。

## Case集約

primary statisticsは`MEASURED` phaseの5反復だけを使う。あるcaseをcompleted集合へ入れる条件は、5反復がすべて存在し、すべて`COMPLETED`であることとする。

- 1反復でも欠ければ`incomplete_case_ids`へ入れる
- statusが反復間で異なれば`mixed_status_case_ids`へ入れる
- warmupはfrontierへ使わない
- 欠測を`NOT_RUN`へ自動変換しない
- 補間は行わず、`interpolation_used`は常に`false`

## Dominance

7 dimensionすべてが以下で、少なくとも1軸が小さいcaseを「より易しい」と定義する。completed frontierはcompleted集合のmaximal points、first-failure frontierは各failure集合のminimal pointsである。

failureは`TIMEOUT`、`MEMORY_LIMIT`、`SOLVER_UNKNOWN`、`PROCESS_FAILURE`、`INVALID_CASE`、`NOT_RUN`を分離する。同一caseの反復に複数failure statusがあれば、該当する各frontier候補へ残す。

## Non-monotonic warning

失敗caseより難しいcompleted caseが存在する場合、単純な単調scaling仮定に反するため、failed case、completed case、failure statusをwarningへ記録する。warningを削除して滑らかなfrontierに見せてはならない。

## Evidence境界

reportはscalability contract digestとexecution protocol digestへ結合し、artifact自身のSHA-256を持つ。gridは460 measured runがすべて存在する場合だけ`COMPLETE`となる。

## 非主張

本reportはhardware性能、12x8x64達成、security verdictではない。hardware statusは`NOT_VERIFIED`であり、GO/PIVOTは次段の独立gateが判定する。
