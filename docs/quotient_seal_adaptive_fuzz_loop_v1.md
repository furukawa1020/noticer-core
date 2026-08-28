# K8-15c Bounded Adaptive Malicious Host Fuzz Loop v1

## 目的

公開観測へ適応するmalicious host探索を、停止条件と判定境界が明示された再現可能な有限loopとして固定する。これは`INJECTED_TEST_FIXTURE`上のharness検証であり、実runtime、実device、hardwareは`NOT_VERIFIED`である。

## 適応選択

K8-15aの10種類のtyped actionを一度ずつ候補にする。次actionの選択wordとparameter wordは、seed、公開context state、直前までのK8-15b corpus digest、action classをdomain-separated SHA-256へ入力して求める。このため同じ公開履歴とseedではbyte-reproducibleであり、private biosignalやprivate traceは選択入力へ入らない。

各stepはaction、公開random word、action program digest、前後の公開state digest、公開observation digest、coverage digest、corpus digest、logical timeを保存する。

## Verdict

| Verdict | 意味 |
|---|---|
| `COUNTEREXAMPLE` | targetがtyped violationと公開witness digestを返した |
| `EXHAUSTED` | 10 action classの有限探索を反例なしで完了した |
| `INCONCLUSIVE` | resource bound、unsupported、checker disagreementで結論不能になった |

`INCONCLUSIVE`は`STEP_BOUND`、`STATE_BOUND`、`TIME_BUDGET`、`UNSUPPORTED`、`CHECKER_DISAGREEMENT`を区別する。logical timeはwall clockではなくtargetが返す決定的cost unitであり、fixtureの実行速度をsecurity evidenceへ混入させない。

## 証拠境界

safe fixtureの`EXHAUSTED`は有限action grammarに反例がなかったことだけを示し、QuotientSeal全体の安全性証明ではない。vulnerable fixtureの`COUNTEREXAMPLE`も注入したtest fixtureへの検出能力だけを示す。K8-15dでcounterexample縮約と独立replayを追加するまで、発見結果を最小反例や独立再現済みとは扱わない。
