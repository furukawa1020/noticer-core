# K7 resumable replication runner v1

K7-16cはK7 package DAGを一つのcommandで実行し、各taskの結果をcanonical JSONへ保存する。

```bash
python -m noticer_core.replication.k7_runner
```

実行前にK7-16bのoffline environment inspectionを行い、`READY`でなければcommandを起動しない。
subprocessはshellを介さず、taskごとのdeadlineと最大output bytesを監視する。raw stdout/stderrは公開artifactへ
保存せず、byte数とSHA-256だけを保持する。statusは`PASS`、`FAILED`、`TIMEOUT`、`UNAVAILABLE`、
`OUTPUT_LIMIT`、`BLOCKED`を区別し、依存失敗、入力欠落、環境不一致を成功へ丸めない。

resumeは保存済みresultのschema、task digest、全input digest、result digestを再計算する。一つでも異なれば
そのtaskを再実行し、生成resultが変わることで後続taskも再検証される。既定のrun logは
`artifacts/k7_replication/run-log.json`であり、task resultとともにGitへcommitしない。

runnerの成功はbounded public software taskの完了だけを表し、security verdict、hardware検証、
独立環境での再現を意味しない。
