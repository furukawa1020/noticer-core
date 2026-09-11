# K7 held-out開封ledger

## 目的

K7-08gは、held-out familyをbackend tuningへ流用できないように、評価前の固定値と結果開封を不可逆なreceipt chainへ分離する。committed precommitは常に`PRECOMMITTED`であり、runtime ledgerだけが`SEALED`、`OPENED`へ進む。

## Precommit bindings

`configs/quotient_forge/heldout_precommit_v1.yaml`は次のdigestを独立に固定する。

- calibration lock: expected status、difficulty、resource policy全体
- corpus: family ID、case digest、AQRS digest
- split: train、development、held-outのfamily列
- bounds: case別state・horizon・observer・faultと共通resource limit
- backend: Cargo/Python lockとsynthesizer、checker、独立oracle実装

text backend componentはCRLFをLFへ正規化してhashするため、WindowsとLinuxのcheckout差だけではdigestが変化しない。実装、依存、bound、split、corpusの変更はstale precommitとして拒否される。

## 状態機械

許可される遷移は次の2本だけである。

```text
PRECOMMITTED -> SEALED -> OPENED
```

最初のreceiptは結果を持たず、固定bindingだけを封印する。2番目は直前receiptのdomain-separated SHA-256とheld-out result bytesのSHA-256を持つ。`OPENED -> SEALED`、2回目の`OPENED`、revision巻き戻し、途中receipt置換は拒否する。

ledgerはcanonical LF-only JSONLで、既存bytesをtruncateまたは置換せず追記する。同一receiptの再試行だけはidempotentに受理する。

## Artifact分離

developmentとheld-outは次の異なるnamespaceへ固定する。

```text
artifacts/quotient_forge/development
artifacts/quotient_forge/held_out
```

receiptにはnamespaceやlocal artifact pathを保存せず、result format、digest、byte countだけを保存する。username、host path、private biosignal、participant identifier、token bytes、key materialは保存しない。開封対象JSONに禁止fieldがあればdigest化前に拒否する。

## 実行

```bash
python -m noticer_core.evaluation.heldout_ledger \
  --config configs/quotient_forge/heldout_precommit_v1.yaml \
  seal --ledger artifacts/quotient_forge/held_out/opening.jsonl

python -m noticer_core.evaluation.heldout_ledger \
  --config configs/quotient_forge/heldout_precommit_v1.yaml \
  open --ledger artifacts/quotient_forge/held_out/opening.jsonl \
  --result artifacts/quotient_forge/held_out/discovery-result.json \
  --result-format noticer.k7.discovery-result.v1
```

runtime ledgerとresultは生成artifactでありGitへcommitしない。

## 非主張

- ledgerはOS filesystemのWORM保証ではない
- SHA-256 bindingは実験設計の妥当性そのものを証明しない
- `SEALED`はheld-out結果を評価済みであることを意味しない
- hardware statusは`NOT_VERIFIED`である
- このledgerだけで新規性、完全性、deployment一般化を主張しない
