# K7 cross-environment replication v1

K7-16fはWindowsとLinuxで独立生成したpublic observationを比較し、semantic artifact一致とplatform固有の
measurement差を別々に記録する。入力は各環境のaudit verdict、package contract digest、semantic artifact
digest map、公開measurement mapである。

```bash
python -m noticer_core.replication.k7_cross_environment \
  --windows artifacts/windows-observation.json \
  --linux artifacts/linux-observation.json \
  --output artifacts/k7_replication/cross-environment.json
```

contractまたはsemantic artifact digestが1件でも異なれば`DISAGREEMENT`となる。tool versionやwall-time
bucketなどのmeasurement差は別ledgerへ残し、semantic disagreementをplatform差として隠さない。
両auditが`PASS`かつsemantic `MATCH`の場合だけ`independent_replication: VERIFIED`となり、それ以外は
`NOT_VERIFIED`を維持する。

CI matrixはvalidatorとnegative controlをWindows/Linuxの両方で実行するが、それ自体を独立実験結果とは
数えない。実artifactを別環境で生成して比較するまで研究上の独立再現は`NOT_VERIFIED`である。
