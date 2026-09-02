# QuotientSeal Go / Pivot / Kill Decision Gate v1

## 目的

K8の最終判断を印象や平均点で決めず、実験前に固定した規則から機械的に導く。これはQuotientSeal software evaluationのdecision gateであり、security proof、臨床判断、hardware検証ではない。

## 非補償原則

判定優先順位は`KILL > PIVOT > GO`である。security、utility、identity attack、reproducibilityのFAILを、performanceや別axisのPASSで相殺しない。点数の加算や重み付き平均は用いない。

`GO`には10 axisすべての`PASS`と全thresholdの充足が必要である。`MISSING`、`NOT_RUN`、`UNSUPPORTED`、`INCONCLUSIVE`は`PIVOT`であり、成功扱いしない。

## Axis

| Axis | FAIL時 | 主な固定条件 |
|---|---:|---|
| manifest | KILL | provenanceとinventoryが有効 |
| reproduction | KILL | 再現runがPASS |
| evidence_audit | PIVOT | completenessとsecret監査がPASS |
| security | KILL | invalid caseが0 |
| utility | KILL | retention ratioが0.90以上 |
| mutation | PIVOT | critical escaped mutantが0 |
| engine | PIVOT | engine disagreementが0 |
| attack | KILL | identity advantageが0.05以下 |
| performance | PIVOT | overhead ratioが2.0以下 |
| ablation | PIVOT | ablation evidenceがPASS |

閾値は研究結果を見てから変更しない。変更する場合はpolicy versionとdigestを更新し、別判定として扱う。

## Digest連鎖

入力はmanifest、reproduction report、evidence audit reportのSHA-256を各axisのartifact digestへ結ぶ。判定reportはcanonical JSON化したpolicyと入力のdigestを持ち、`decision_id`を両digestから導出する。report自身は`integrity`以外の全fieldをSHA-256で封印する。

## 感度と反証

reportは、他のgateがすべてPASSという仮定の下で各axisをFAILまたはINCONCLUSIVEへ変えた場合の判定と、各threshold違反時の判定を列挙する。KILL条件はfalsification conditionとして別途保存する。

## 境界

- `PREDECLARED_RULE_EVALUATION`
- `SOFTWARE_DECISION_GATE`
- `NOT_A_PROOF`
- `NOT_VERIFIED`

`GO`は指定policy下のsoftware evidenceがgateを通ったことだけを意味する。Polar Verity Senseを含む実機接続やhardware上の性質を主張しない。優先権や`world-first`も主張しない。
