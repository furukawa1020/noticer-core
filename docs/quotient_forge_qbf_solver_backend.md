# QuotientForge QBF solver boundary

K7-05cは、外部QBF solverをsecurity oracleではなくbounded candidate generatorとして隔離する。

## 固定するprovenance

- solver: CAQE 4.0.2
- official tag commit: `62ee7692dada5236307f8652234ed7a743651eb7`
- official source archive SHA-256: `d09ad720a29eedb27b64182eadd51820b5ac8f30784051f033cdf3972b4e5d37`
- manifest、platform、fixed argv、timeout、seed、finite bound
- build後binaryのSHA-256をinstall receiptへ保存し、実行直前に再照合

公式prebuilt binaryは存在するものとして扱わない。任意CIはSHA検証済みsourceからLinux binaryをbuildし、生成binary hashをreceiptへ残す。

Windows command、path、receipt、binary再hashのadapter契約はsolver-free CIで固定する。一方、CAQE 4.0.2の依存する`cryptominisat`と`jemalloc`はGitHub Windows runnerのMSVC/GNU双方でbuildできなかったため、Windows実solverは`NOT_VERIFIED`とする。installerはWindows指定を明示的に拒否し、動作済みと誤認させない。

## Result taxonomy

`SAT`、`UNSAT_AT_BOUND`、`UNKNOWN`、`TIMEOUT`、`MALFORMED`は相互変換しない。CAQEのexit code 10/20は通常の非zero終了であるため、statusは厳格なQDIMACS output行から分類する。矛盾する複数status、output上限超過、未知形式は`MALFORMED`になる。

`UNSAT_AT_BOUND`はmanifestに記録されたfinite machine/horizon boundだけの結果であり、global unrealizableへ昇格しない。

## SATの扱い

K7-05cではmodel decoderと独立AQRS checkerをまだ接続しない。そのためSAT artifactは常に次を保持する。

```text
candidate_status = PENDING_INDEPENDENT_CHECK
candidate_accepted = false
bounded_only = true
```

solver出力だけでcandidateを受理する経路はない。decodeと独立checkはK7-05dで追加する。

## Process boundary

実行はshellを使わず、既存`run_bounded_process`を通す。queryは専用temporary fileへ書き、stdin/stdout/stderr、timeout、UTF-8、kill/reapの既存上限を維持する。binaryまたはreceiptのhash・source revision・platform・manifest digestが一致しなければ実行前にfail closedとする。

## 非主張

- CAQE自体の正しさは主張しない
- unbounded completenessは主張しない
- 特定QBF solverの性能優位性は主張しない
- hardwareまたはPolar Verity Sense接続の検証済み状態は主張しない
