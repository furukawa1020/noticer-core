# K7 independent replication package v1

## Scope

K7-16aはK7の公開software evidenceを再実行するtask DAGを固定する。実験自体の実行、toolchain導入、
figure生成、独立環境での再現、最終GO・PIVOT・KILL判定は後続Issueで扱う。この契約やCI通過は
security verdictではなく、hardware、Polar Verity Sense、private biosignalは`NOT_VERIFIED`である。

## Contract

`replication/k7_package_contract_v1.json`は次をtaskごとに固定する。

- canonical task IDとevidence category
- shellを介さないcommand argvとrepository-relative cwd
- repository inputと`artifacts/k7_replication/`配下のgenerated input・output
- direct producer dependency
- timeoutと最大output bytes

loaderはunknown field、重複ID・output、cycle、unknown dependency、producerを依存に含まないartifact input、
絶対host path、private marker、範囲外resource limitを拒否する。taskは決定的なtopological orderへ並べ、
各task、contract全体、lock全体をdomain-separated SHA-256で束縛する。lock検証は保存済みdigestを
信頼せずfull recomputationする。

## Failure semantics

本Issueはtaskの実行結果を作らない。後続runnerはmissing、timeout、backend unavailable、unknown、
inconclusiveを別statusとして保持し、依存taskの失敗を後続taskの成功で覆ってはならない。
generated lock、run log、resultは`artifacts/`配下へ出し、Gitへcommitしない。
