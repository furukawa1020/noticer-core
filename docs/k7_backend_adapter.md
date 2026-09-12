# K7 solver・checker backend adapter v1

## 目的

K7-09cは`reference`、`cegis`、`smt`、`qbf`を同じrun artifactへ正規化するprocess境界である。adapterはsolver結果を合成せず、指定された実binaryをshellなしで起動し、そのprocessが新規生成した`backend-result.json`だけを受理する。`mock_result_allowed`は常に`false`である。

## Backend result契約

backendはcase ID、backend ID、status、candidate count、checker node count、solver call count、checker verdict、evidence digestを出力する。`COMPLETED`には`VERIFIED`が必須であり、未検証candidateは完了扱いにしない。

backendが自己申告できるstatusは次だけである。

- `COMPLETED`
- `SOLVER_UNKNOWN`
- `INVALID_CASE`

`TIMEOUT`、`MEMORY_LIMIT`、`PROCESS_FAILURE`はadapterがprocessとresource observationから決める。backendの自己申告でhost resource failureを偽装できない。

## Evidence binding

normalized artifactは次を結合する。

- version probeの先頭行
- 実行binaryのSHA-256
- backend result、stdout、stderrのSHA-256
- candidate、checker node、solver callの各count
- K7-09bのdirect-child resource artifact

command、PID、hostname、username、private payloadはpublic artifactへ記録しない。stdoutとstderrも内容ではなくdigestだけを正規化artifactへ含める。raw process filesとgenerated artifactは`artifacts/`以下に置き、Gitへcommitしない。

## Fail-closed分類

timeout、memory超過、nonzero exit、artifact欠落、identity不一致、未知field、不正count、checker未検証を区別する。artifactが存在していてもprocessがnonzero exitなら`PROCESS_FAILURE`を優先する。

外部SMT/QBF solverが未導入の環境では成功を合成せず、後続runnerが`NOT_RUN`として記録する。実solverのpin、version、binary digestは既存solver manifestと本adapterの観測を併用する。

## 非主張

この層は12x8x64の完走、solverのsoundness、checkerの完全性、hardware性能を主張しない。実験順序と反復、resumption、frontier、GO/PIVOT判定は後続Issueで固定する。
