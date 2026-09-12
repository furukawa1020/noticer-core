# K7 scalability契約 v1

## 目的

K7-09aは性能値を報告する段階ではない。後から都合のよい軸、上限、backend、失敗分類へ変更できないよう、測定前にscalability protocolを凍結する。hardware上の実測状態は`NOT_VERIFIED`であり、この文書や設定は12x8x64の達成を主張しない。

## 実験design

`configs/quotient_forge/k7_scalability_contract_v1.yaml`は次の7軸を固定する。

- plant states
- machine states
- horizon
- observer count
- fault-state count
- output alphabet
- quotient class count

designはbaseline、baselineから1軸だけを増加させるone-factor sweep、全軸最大のtargetからなる。1 backendあたり23 profile、4 backendで92 caseである。これにより軸ごとの増加を観測しつつ、12 plant states・8 machine states・horizon 64を省略できない。

各case IDはprofile、backend、reduction、全dimensionをdomain-separated SHA-256へ入力して決める。同一契約からはWindowsとLinuxで同じIDと契約digestが得られる。

## Backendと上限

`reference`、`cegis`、`smt`、`qbf`を、それぞれ明示したreduction configurationと組にして固定した。ここで固定するのは識別子と上限であり、実solver/checker adapterはK7-09cで実装する。

wall time、memory、candidate、checker node、solver callの上限はすべて事前固定値である。後続runが上限へ到達しても、`COMPLETED`へ読み替えてはならない。

## Status taxonomy

結果は次の排他的statusを保持する。

- `COMPLETED`
- `TIMEOUT`
- `MEMORY_LIMIT`
- `SOLVER_UNKNOWN`
- `PROCESS_FAILURE`
- `INVALID_CASE`
- `NOT_RUN`

`TIMEOUT`、`MEMORY_LIMIT`、`SOLVER_UNKNOWN`は別の観測であり、いずれも成功でも`UNSAT`でもない。12x8x64 caseが`COMPLETED`でなければ、そのbackendはgate達成として扱えない。

## Artifact境界

後続の測定artifactは`artifacts/quotient_forge/scalability`以下へ生成し、Gitへcommitしない。契約にはprivate biosignal、subject identity、token、raw traceを含めない。実行環境、warmup、反復、実行順、resource sampler、frontier、GO/PIVOT判定は後続の分割Issueでdigest-boundにする。

## 非主張

この契約は性能測定、hardware validation、実環境でのscalability、deployment一般化を示さない。また、候補primitiveの新規性や完全性を主張するものではない。
