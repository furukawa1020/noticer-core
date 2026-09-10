# K7 negative benchmark corpus v1

## 目的

成功caseだけに偏らないため、事前登録済みnegative 8 familyを固定する。結果は`UNSAT_AT_BOUND`と`INVALID_SPEC`を明示的に分離し、timeout、resource limit、checker inconclusiveをnegative判定へ昇格させない。

## 分類

| family | split | status | 最小反証理由 |
|---|---|---|---|
| `negative_missing_authorized_output` | train | `UNSAT_AT_BOUND` | authorized outputがalphabetにない |
| `negative_secret_dependent_retry` | train | `INVALID_SPEC` | private値がretry traceへ流れる |
| `negative_impossible_deadline` | development | `INVALID_SPEC` | action windowがhorizon外 |
| `negative_failure_leak` | development | `INVALID_SPEC` | private failure値が公開される |
| `negative_quotient_merge` | development | `INVALID_SPEC` | private fieldがeraseされない |
| `negative_private_carryover` | held_out | `INVALID_SPEC` | private値がservice aliasへ残る |
| `negative_observer_omission` | held_out | `INVALID_SPEC` | action service observerがない |
| `negative_unauthorized_cover_action` | held_out | `UNSAT_AT_BOUND` | cover actionはauthorizationを満たさない |

期待status、reason code、type diagnosticは`negative_refutations_v1.yaml`へ固定する。held-outの期待値も同じindexに含め、実験後の書換えを許さない。

## 検査境界

`INVALID_SPEC` 6件はcanonical parserを通した後、semantic type checkerが指定diagnosticで拒否し、solverやproduct checkerへ到達しない。`UNSAT_AT_BOUND` 2件はwell-formed `SynthesisProblem`へlowerし、固定state boundの全探索が`Unrealizable`を返すことを確認する。代表candidateをsolver-independent checkerへ直接渡し、`Verified`になればtestをFAILさせる。

case envelopeとrefutation indexはraw private value、biosignal、person/device identifierを含まない。
