# K8-16b Deterministic Software Fixture Runner v1

## 目的

K8-16aのmeasurement contractを直接使い、compile、parse、extract、validate、context check、capsule、runtime、QuotientPadの公開software fixture costを決定的に収集する。実compiler、実engine、実hardwareのbenchmarkではない。

## Planとinvocation

planは`stage × metric × public benchmark case alias`の重複しないtask列である。plan digestはrun configへ固定する。各taskについてwarmupを先に実行し、その後measured iterationを実行する。warmup outcomeはinvocation traceへ残すがmeasurement campaignのsampleへ混ぜない。

各invocationのrandomness wordはseed、plan digest、task index、phase、iterationからdomain-separated SHA-256で導出する。同じfixture implementation、seed、planではartifactがbyte-identicalになる。

## Outcome境界

fixtureは`SUCCESS(value)`、`FAILURE(reason)`、`INCONCLUSIVE(reason)`だけを返す。panicは`FAILURE/TOOL_ERROR`へ変換する。unsupported、resource bound、timeoutは0 costやsuccessへ変換せずinconclusiveのままcampaignへ入れる。

runnerはwall-clock taskとwall-clock opt-in configを拒否する。収集対象はlogical fuel、host call count、memory access count、artifact bytes、peak memory bytes、scaled attack scoreだけである。

## Artifact

run artifactはplan、config、sanitized metadata、全warmup/measured invocation、measured campaign、status countを含む。公開randomness、sample digest、plan digest、summaryを完全再計算する。provenanceは`SOFTWARE_FIXTURE`または`INJECTED_TEST_FIXTURE`、hardwareは`NOT_VERIFIED`である。生成artifactはGitへcommitしない。
