# K7 resumable scalability runner v1

## 目的

K7-09eは644 runの長時間実行を、欠落・重複・結果置換を許さず再開するappend-only runnerである。実験結果そのものや12x8x64達成を主張するものではない。

## 二段階commit

各scheduled runについて、runnerは次の順でgenerated artifactを作る。

1. `runs/<run-id>/backend.json`を排他的に新規作成する
2. backend artifactを検証しSHA-256を計算する
3. `checkpoints/<ordinal>-<run-id>.json`を排他的に新規作成する

process停止が1と3の間で起きた場合、resumeは既存backend artifactのidentityとstatusを再検証してcheckpointへ回収し、backendを再実行しない。既存fileの上書きは行わない。

## Resume validation

`run-lock.json`はexecution protocol digest、scalability contract digest、backend binding digest、schedule長を固定する。resume時は次をすべて再検証する。

- checkpointがordinal 0から連続したschedule prefixである
- run ID、case ID、backend、phase、repetition、attempt、seedがscheduleと一致する
- protocol、scalability contract、backend bindingのdigestが一致する
- backend artifactが存在し、そのdigest、identity、statusがcheckpointと一致する
- `previous_checkpoint_sha256`が直前checkpointを指す
- `mock_result_allowed`が`false`である

異なるbinding、欠落checkpoint、artifact改変、未知status、identity不一致はfail-closedで再開を拒否する。失敗statusもcheckpointされ、削除や成功への置換は行わない。

## Artifact境界

run lock、backend artifact、checkpointはすべて`artifacts/quotient_forge/scalability`以下のgenerated evidenceであり、Gitへcommitしない。source treeへ測定結果を書かない。

## 非主張

runnerはbackendのsoundness、hardware performance、frontier、GO/PIVOTを判定しない。具体的な4 backend bindingは追補Issueで接続し、frontierと最終gateは後続Issueで評価する。
