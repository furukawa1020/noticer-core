# K7 execution protocol v1

## 目的

K7-09dはscalability結果を見る前にwarmup、反復、seed、実行順、失敗保持を固定する。結果を見て順序や反復数を変更すること、失敗runだけを捨てること、held-out開封後にprotocolを書き換えることを禁止する。

## 事前固定値

- master seedは`260817`
- warmupは各case 2回
- 測定対象の反復は各case 5回
- warmupは保存するがprimary statisticsには含めない
- 各runの最大attemptは1回
- retryで元attemptを置換しない
- failed resultは`PRESERVE`、欠測は`NOT_RUN`
- adaptive reorderingは禁止

凍結済み92 scalability caseに対して合計644 runを生成する。run ID、ordinal、phase、repetition、profile、backend position、case ID、backend ID、seed、attemptはすべて決定論的である。

## 実行順

profile順はmaster seedとprofile名のSHA-256順で固定する。各profile内のbackend順は`reference`、`cegis`、`smt`、`qbf`をLatin rotationし、反復とprofile位置による順序biasを分散する。測定5回では、各backendが各positionへ1回以上入り、position回数差は最大1である。

## Digest binding

protocolはK7-09a scalability contract digestへ結合する。protocol digestには全644 runとretention policyを含める。held-out ledgerの`OPENED`後は、同一digest以外へのtransitionを拒否する。開封recordはprotocol digestを持たなければならない。

## Artifact境界

後続runnerはwarmupを含む全attemptを`artifacts/quotient_forge/scalability`以下へ保存し、Gitへcommitしない。失敗や欠測を削除してscheduleを詰め直してはならない。

## 非主張

このprotocolは実測性能、12x8x64達成、hardware validation、solver soundnessを示さない。resource samplerとbackend adapterをどう反復実行するかを固定するだけであり、集計とGO/PIVOT判定は後続Issueが担う。
