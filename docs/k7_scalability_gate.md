# K7 12x8x64 GO・PIVOT gate v1

## 目的

K7-09gは12 plant states・8 machine states・horizon 64のtarget outcomeを、結果確認前に固定した非補償的ruleで判定する。未達、欠測、unknownをGOへ読み替えない。

## 判定rule

- grid欠測またはnon-monotonic warningがあれば`BLOCKED`
- target backendの欠落、`SOLVER_UNKNOWN`、`PROCESS_FAILURE`、`INVALID_CASE`、`NOT_RUN`があれば`BLOCKED`
- blockerがなく、1つ以上のbackendがtargetを`COMPLETED`なら`GO_CANDIDATE`
- 全backendが`TIMEOUT`または`MEMORY_LIMIT`なら`PIVOT`
- どの条件にも安全に分類できなければ`BLOCKED`

`GO_CANDIDATE`は研究継続候補であり、security PASSやdeployment readinessではない。

## Digest binding

manifestはcorpus、split、bound、backend、resultの5 digestを必須とし、frontier artifact digestも再検証して結合する。いずれかの欠落、形式違反、frontier改変はmanifest生成を拒否する。

## Claim境界

- `deployment_generalization = FORBIDDEN`
- `hardware_status = NOT_VERIFIED`
- `security_interpretation = RESEARCH_CONTINUATION_GATE_ONLY`

toy caseやsynthetic resultから実環境性能へ一般化しない。generated manifestは`artifacts/`以下へ保存し、Gitへcommitしない。
