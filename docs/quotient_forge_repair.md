# QuotientForge Typed Repair and Pareto Frontier

## 1. 目的

`quotient-forge-repair`は、K6-04 checkerが反例を返すfinite release machineを、許可されたrelease IR operatorだけで修復するbounded search engineである。

repair対象は`SynthesisProblem`、`ReleaseMachine`、typed `Release`である。Rust AST、source text、arbitrary callbackを入力にせず、application codeを書き換えない。

## 2. 許可operator

operator集合は次の8種類へ閉じる。

- `cutoff`: public fieldを最大byte境界へ切る
- `bucket`: numeric public fieldを固定幅bucketへ写像する
- `fixed_size`: observer-visible size classを固定labelへ写像する
- `cover`: silent releaseをemitted coverへ置換する
- `failure_normalization`: failure fieldをpublic constantへ正規化する
- `public_retry_reconnect`: retry/reconnect fieldをpublic markerへ正規化する
- `service_separation`: service fieldをservice-scoped markerへ置換する
- `release_window`: cover slotとdelay stateを追加してreleaseを遅延する

operatorはcanonical rank順に1回ずつ適用する。順序違いによる重複探索を避け、同じmachine/output fingerprintのvariantも除外する。

## 3. Known violation対応

- `ImmediateRelease`: `release_window`でcoverを先行させ、許可slotへactionを移す
- variable-size trace: `fixed_size`でobserver-visible size classを固定する
- secret-dependent retry/reconnect: `public_retry_reconnect`でpublic markerへ正規化する
- failure leakage: `failure_normalization`でfailure reasonを統一する

これらはhard-coded AETSを返す処理ではない。各candidateはsource machine/outputへoperatorを適用して導出し、K6-04 checkerで再検証する。

## 4. 透明repair距離

distanceは次の順の辞書順vectorである。

1. changed transition数
2. changed output数
3. added state数
4. added cover release数
5. added latency slot数

sourceとcandidateの共有table/output部分を直接比較し、追加要素もchanged countへ含める。

## 5. Pareto frontier

各verified candidateは次の3 objectiveを持つ。

- 透明repair距離
- K6-06と同じruntime cost vector
- applied operator数

3 objectiveすべてで劣らず、少なくとも1 objectiveで優れるcandidateだけが他candidateをdominateする。非支配点だけを保持し、canonical順に並べる。

frontier件数は`max_frontier`で制限する。非支配点が上限を超えた場合、`truncated = true`を返し、完全frontierと誤認させない。

## 6. Provenance

各repair pointは次を保持する。

- source machine/outputのstable fingerprint
- 実際に適用したoperator chain
- repaired machine
- repaired output alphabet
- distanceとruntime cost

fingerprintはlineageとdedupのためのdeterministic識別子であり、署名または暗号学的artifact hashではない。artifact真正性にはK6-05 CAQT hashを使用する。

operator chainがない外部templateをrepair resultとして注入する経路は公開しない。

## 7. Outcome

- `Repaired`: 1件以上のchecker-verified非支配解
- `NoRepair`: 指定operator深さとvariant範囲を完走したが解なし
- `Inconclusive`: variant、time、checker resource上限へ到達

resource exhaustionを`NoRepair`へ変換してはならない。

## 8. 非保証事項

このengineは次を保証しない。

- 許可operator集合外に存在するrepairの不存在
- 無限traceのsecurity
- frontier上限超過時の完全Pareto集合
- source fingerprintの暗号学的衝突耐性
- DSL/Rust sourceへの自動patch
- hardware timing、BLE radio、OS scheduling

code generationとNoticer adapterは後続Issueで実装する。
