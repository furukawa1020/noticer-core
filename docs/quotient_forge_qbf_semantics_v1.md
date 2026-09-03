# QuotientForge bounded QBF semantics v1

## 位置づけ

K7-05bは、AQRSの有限safety-gameをQDIMACSへ落とすreference compilerである。外部QBF solver、model decoder、無限状態synthesis、一般HyperLTL synthesisはこの段階の対象外とする。

中心となる量化順序は次である。

```text
exists machine table.
forall action-equivalent private-history pair, environment trace, fault trace.
exists dependent witness.
    complete observer trace equality
    and hard utility/deadline/retry/reconnect/fault obligations
```

machine choiceはtraceより前に固定される。同じaction semanticsを持つprivate historyごとに別のmachineを選ぶことはできない。

## 有限reference encoding

v1 compilerは、明示されたmachine-state boundまでのcanonicalなrelease machineと、明示されたhorizon内のinitial pairおよびenvironment/fault traceを有限列挙する。各candidate/scenarioの受理関係は既存AQRS checkerと同じstep semanticsで評価し、`exists machine / forall scenario / exists witness`のCNFへコンパイルする。

これは意味論を固定し、後続のsymbolic encoderと外部solverをdifferential testするための小規模oracleである。大規模探索の性能手法ではない。

## Action-equivalence premise

有効なuniversal assignmentは次をすべて満たす。

- initial pairのaction semanticsが等しい
- private historyが異なる
- 各slotでenvironment inputが一意に選ばれる
- environment inputとfault selectorが一致する

QBFではuniversal bit-vector自体を制約できないため、有効なscenario encodingに一致した場合だけhard consequentを要求する。空のinitial-pair集合、空のinput集合、空のscenario集合は「自明に真」とせずfail closedにする。

## Hard consequent

各有効scenarioでは、horizon全体について以下を同時に要求する。

- release presenceの一致
- observerが見える全fieldの一致
- observerが見えるaction列の一致
- action authorization
- exactly-once、trigger、deadline
- fault発生後のrecovery deadline
- retry/reconnectをactionまたはvisible fieldとしてモデル化した場合の同一性とutility充足

左右のrunが次状態で異なるaction semanticsへ移った時点から、そのsuffixはaction-equivalence premiseの外側として扱う。この境界は既存product checkerと同じである。

## Artifact

`QbfCompilation::write_to_directory`は次を保存する。

```text
<directory>/
├── semantics.json
└── qdimacs/
    ├── metadata.json
    └── problem.qdimacs
```

`semantics.json`はschema version、量化順序、seed、plant/machine/horizon/output/candidate/scenario bound、canonical machine表、private pair、environment/fault trace、受理matrix、matrix SHA-256、QDIMACS SHA-256を含む。generated artifactはGitへcommitしない。

## 独立oracleとnegative mutant

`evaluate_qbf_truth`はAQRS transition evaluatorを呼ばず、symbolic clauseと量化blockを直接全称・存在評価する。小規模corpusでは、このtruth valueを`quotient-forge-synth`の独立exhaustive backendと比較する。

`compile_quantifier_order_mutant_fixture`は意図的にmachine choiceをuniversal traceの後へ移す。このmutantはscenarioごとに別machineを選べるためunsoundであり、metadataには常に`non_production_mutant: true`を残す。本番backendとして使用してはならない。

## 非主張

- finite bound外のrealizabilityは主張しない
- infinite-state gameのsoundness/completenessは主張しない
- 任意HyperLTL synthesisへの一般化は主張しない
- QBF導入自体を研究新規性として扱わない
- 外部solverの結果はK7-05c、decoded modelの独立検証はK7-05dで扱う
