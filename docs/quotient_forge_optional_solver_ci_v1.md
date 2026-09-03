# QuotientForge Optional Solver CI v1

## 目的

通常のpushとpull requestでは外部solverを取得せず、solver-free exhaustive modeを必須gateとして維持する。明示的な`workflow_dispatch`だけで、pinned z3/cvc5をWindows/Linux上で検証する。

## 手動matrix

`run_solver=true`で次の4 jobを独立実行する。

- cvc5 1.3.4 / Linux x86_64
- cvc5 1.3.4 / Windows x86_64
- Z3 4.16.0 / Linux x86_64
- Z3 4.16.0 / Windows x86_64

各jobは別install rootと別artifact名を使用する。solver間、platform間で証跡を混合しない。

## Fail-closed install

installerは`configs/quotient_forge/solver_matrix_v1.json`だけをsource of truthとし、次を満たさない取得・展開を拒否する。

- network policyが`DOWNLOAD_ONLY_WITH_SHA256`
- HTTPSの公式GitHub release URL
- redirect先hostが許可list内
- download sizeが256 MiB以下
- archive SHA-256がpinned値と一致
- entry数と展開後sizeが上限内
- path escape、absolute path、重複path、symbolic linkがない
- manifest記載の実行binaryがregular fileとして存在

archive hashに加え、展開後binaryの観測SHA-256をinstall receiptとsolver resultへ保存する。

## 実solver smoke

Rust CLIはbounded runtimeを用いて3 capability probeを実行し、固定QF_LIA問題`smoke_x = 11`を解く。SAT modelはsolver出力と独立した小さなcheckerで`smoke_x = 11`を確認してから`ACCEPTED`にする。

各jobは次をuploadする。

- `install.json`: release、asset SHA、binary SHA、platform
- `probe.json`: capability別の入出力digestと判定
- `result.json`: 5値result、version、matrix SHA、実argv、timeout、seed、search bound

upload stepは`always()`で実行する。probe後の`UNKNOWN`、timeout、出力上限などでsmokeが失敗しても、生成済み証跡を回収する。hash不一致はbinaryを実行せずjobを失敗させる。

## 非主張

- optional CI成功はsolver自体の正しさを保証しない。
- 4環境以外のplatform互換性を保証しない。
- `UNSAT_AT_BOUND`をglobal unrealizableへ昇格しない。
