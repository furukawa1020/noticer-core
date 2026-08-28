# K8-15b Deterministic Coverage Corpus v1

## 目的

adaptive malicious host fuzzerが利用するfeedbackとcorpusを、seedと公開観測が同じならbyte-identicalになる契約として固定する。これは攻撃成功の実測ではなく、`INJECTED_TEST_FIXTURE`によるharness契約である。hardwareは`NOT_VERIFIED`とする。

## 公開feedback

coverage pointは次の5種類だけを受け付ける。

| 種類 | 入力 |
|---|---|
| `TARGET_BLOCK` | 公開target block ID |
| `PRODUCT_STATE` | 公開product source/target state |
| `OBSERVER_DIVERGENCE` | observer profile、divergence code、公開trace digest |
| `CONTEXT_STATE` | step、service alias、connection state、公開state digest |
| `UTILITY_VIOLATION` | obligation ID、violation code、public slot |

private biosignal、private trace、secret key、stable subject identifierをcoverage keyへ入力するAPIは設けない。

## 決定性と完全再計算

各pointは型付きcanonical JSONをdomain-separated SHA-256へ入力する。feedback、corpus entry、corpus全体も別domainでdigestを計算し、読み出し前と挿入前に下位artifactから完全再計算する。同一IDが異なるpointを指す場合はcollisionとしてfail-closedにする。

corpus entryはcoverage数の降順、action数の昇順、entry digestの昇順で並べる。既存unionへ新しいcoverageを加えないentryは保持しない。global coverageはcoverage IDの昇順かつ重複なしで保存する。

## Boundと判定境界

entry数、coverage point数、entryごとのaction数には設定可能なhard boundを置く。bound到達、digest不一致、非canonical順序、collisionを成功や安全性証拠へ読み替えない。K8-15c以降はこのcorpusを探索feedbackとして再利用し、timeoutやstate boundを`INCONCLUSIVE`として別途記録する。
