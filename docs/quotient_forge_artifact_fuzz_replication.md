# QuotientForge artifact fuzz replication v1

## Scope

K7-15gは、DSL/import graph、canonical JSON IR、CAQT binary、solver model、
codegen artifactの5つのbounded fuzz targetを、同じ公開replication contractへ束縛する。
これはfuzz harnessとartifact parserの回帰検出能力を再現するためのsoftware-only契約であり、
安全性証明、実機検証、科学的counterexample、世界初の主張ではない。

## Frozen contract

`configs/quotient_forge/artifact_fuzz_replication_v1.json`は、32 byte seed、target ID、
clean-checkout用argv、公開seed corpus、入力・case数・timeout上限を固定する。commandはshell文字列ではなく
argvとして保持し、絶対host pathを許可しない。

結果statusは次の4種類を保持し、欠測や多数決で`PASS`へ丸めない。

| Status | Meaning |
|---|---|
| `PASS` | 指定されたbounded caseで異常を検出しなかった |
| `CRASH` | parserまたはharnessが異常終了した |
| `TIMEOUT` | 固定resource limit内に完了しなかった |
| `DISAGREEMENT` | 独立実装、round-trip、または期待値との不一致を検出した |

reportはcase inputの公開hex、SHA-256、coverage proxy、target digest、spec digest、report digestを含む。
private/secret/subject markerと絶対host pathは拒否する。corpus縮小は検出predicateを保つbyte削除を固定順で
反復し、どの1 byteを追加削除しても再現しない1-minimal inputを返す。

## Public reproduction

最初にspec内の各`command`をclean checkoutから実行し、その結果を次の形のJSON配列として保存する。

```json
[{"cases":[{"case_id":"seed","input_hex":"00","status":"PASS"}],"coverage_proxy":{"accepted_mutations":1,"executed_cases":1,"max_depth":1},"target_id":"dsl-import-graph"}]
```

5 targetすべてのobservationを含めてreportを生成する。

```bash
python -m noticer_core.evaluation.artifact_fuzz_replication \
  --spec configs/quotient_forge/artifact_fuzz_replication_v1.json \
  --observations artifacts/k7_artifact_fuzz/observations.json \
  --output artifacts/k7_artifact_fuzz/report.json
```

生成したobservation、縮小corpus、reportは`artifacts/`配下に置き、Gitへcommitしない。
同じspecとobservationからbyte-identicalなcanonical JSONを再生成できないreportは受理しない。
