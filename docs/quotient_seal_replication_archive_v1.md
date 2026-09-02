# QuotientSeal Deterministic Replication Archive v1

## 目的

K8で得たsoftware evidenceを、第三者が内容と判定経路を再検査できる固定packageへ閉じる。生成物は`artifacts/`配下へ置き、Gitへcommitしない。

## 収録契約

archiveは14個のallowlist payloadと`archive-index.json`だけを含む。契約、manifest、reproduction report、evidence index/audit、decision input/report、exact command、非成功台帳、Studio export summaryを分離して保存する。未知file、欠落、symlink、path escape、秘密候補を拒否する。

decision policyと入力を同梱し、verifierが判定を再実行する。decision input内のmanifest、reproduction、audit digestは実際の収録byteと一致しなければならない。別fileのPASSで不一致を相殺しない。

## Byte決定性

- entryはPOSIX canonical pathの辞書順
- timestampは`1980-01-01 00:00:00`
- modeは`100644`
- compressionは`ZIP_STORED`
- comment、extra field、暗号化flagは不使用
- JSONはcanonical UTF-8とSHA-256で封印

同じstaging byteとpolicyから作った2つのZIPはbyte単位で一致する。既存outputは上書きせず、入力の取り違えをfail closedにする。

## 実行

```bash
python scripts/build_quotient_seal_archive.py \
  --staging artifacts/quotient-seal-staging \
  --archive artifacts/quotient-seal-replication.zip \
  --report artifacts/quotient-seal-final-report.json

python scripts/build_quotient_seal_archive.py \
  --verify \
  --archive artifacts/quotient-seal-replication.zip \
  --report artifacts/quotient-seal-final-report.json
```

commandはnetwork accessやdependency installを行わない。stagingへ入れる各実験成果物は先行runnerで生成する。

## 最終report

sidecar reportはarchive SHA-256、index SHA-256、policy、source commit、decision、exact command数、非成功件数、検証checkを結ぶ。時刻や絶対pathを含めないため、同じarchiveから常に同じreportが得られる。

## 境界

- `DETERMINISTIC_ARCHIVE`
- `SOFTWARE_EVIDENCE_ONLY`
- `NOT_A_PROOF`
- `NOT_VERIFIED`
- `NO_PRIORITY_CLAIM`

archiveのPASSはpackage完全性と指定contractの検証結果である。security proof、実機検証、Polar Verity Sense接続、臨床的有効性、優先権を意味しない。
