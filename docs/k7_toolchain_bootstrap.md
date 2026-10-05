# K7 toolchain bootstrap inspection v1

K7-16bは環境を変更するbootstrap installerではなく、repository内のpinと現在のcommand versionを
offlineで照合するfail-closed inspectorである。network access、download、package install、PATH変更は行わない。

`replication/k7_toolchain_lock_v1.json`はPython 3.11系、Rust 1.93.0、Node 24系、Lean 4.30.0、
cvc5 1.3.4、Z3 4.16.0を、それぞれrepository source markerへ結ぶ。inspectorはsource fileのSHA-256を
再計算してからversion commandをshellなし・10秒上限で実行する。

```bash
python -m noticer_core.replication.k7_bootstrap
```

既定出力は`artifacts/k7_replication/environment.json`でありGitへcommitしない。各toolは`MATCH`、
`MISSING`、`MISMATCH`、`ERROR`のいずれかとなり、全件`MATCH`以外はoverall `BLOCKED`とexit code 2を返す。
WindowsとLinuxで同じschemaを使うが、reportのplatform fieldと検出versionは環境測定値なので、
byte-identicalであるとは主張しない。環境検査の成功はsecurity verdictやhardware検証ではない。
