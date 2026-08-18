# QuotientSeal held-out mutation campaign runner v1

## Split contract

K8-11bはmodule familyとcompiler configurationの両方をdevelopment・held-outへ固定し、
片方だけが異なるcross-split seedを拒否する。splitは
`configs/quotient_seal/mutation_split_v1.yaml`で管理し、K8-10の固定compiler config IDを
そのまま再利用する。

held-out module familyやnightly configをdevelopment結果に合わせて変更してはならない。
同じidentifierを両splitへ含める設定、未知identifier、cross-split pairはcampaign開始前に
fail-closedとなる。

## Artifact contract

campaign IDは次の値だけからSHA-256で決定する。

- campaign schema version
- split contract全体
- development / held-out区分
- module family
- compiler configuration
- evaluator ID
- seed WASM SHA-256

時刻、絶対output path、乱数をIDへ含めない。各mutantのWASM、JSON record、campaign manifestを
`artifacts/quotient_seal_mutation/<campaign-id>/`へ保存し、Gitへcommitしない。既存pathに異なる
byte列がある場合は上書きせずcollisionとして停止する。同じbyte列の再実行だけを許可する。

## Verdict preservation

runnerは`KILLED`、`ESCAPED`、`INCONCLUSIVE`の三値だけを保存する。mutantを生成できない場合は
`INCONCLUSIVE/mutation_not_applicable`とし、artifactを捏造しない。独立checker未接続のCLIは
全生成mutantを`INCONCLUSIVE/checker_not_configured`とする。

escaped mutantを削除・非表示にする機能は持たない。evaluatorが`ESCAPED`を返したWASMとrecordも
他の結果と同じartifact treeへ必ず保存する。

## 現在の検証状態

このrunnerの決定性とsplit拒否経路はsynthetic fixtureで検証する。実compiler output、held-out
module、独立checkerを用いたcampaignは #133完了後に実行するまで`NOT_VERIFIED`である。

