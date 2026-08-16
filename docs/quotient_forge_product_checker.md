# QuotientForge Product Checker

## 1. 目的

`quotient-forge-check`は、Action-Quotient Release Synthesis（AQRS）の候補release transducerを、solverとは独立に検査する有限・有界checkerである。

検査対象は、action semanticsが等しくprivate historyが異なる二走である。両走へ同一のpublic inputとfault inputを与え、各logical slotで全observerの観測を比較する。

本checkerはsolverのモデル、最適性主張、SAT/SMT証明を信用しない。明示された有限遷移系をpredecessor付きBFSで直接全探索する。

## 2. 入力境界

checker入力は`CheckerModel`であり、次を明示する。

- 有限state集合
- stateごとのaction semantics IDとprivate history ID
- action-equivalentかつprivate-distinctなinitial pair
- 共通のpublic/fault environment input
- stateとinputに対して全域なrelease transition
- observerごとの可視fieldとaction可視性
- authorized action obligationとrecoverable fault obligation
- 検査horizon

`quotient-forge-ir::CompiledModel`はcompile-time compatibility markerとして依存関係を固定する。K6-04ではIR内部へprivate acquisition型を追加せず、具体的loweringはfrontend/synthesis統合時に実装する。

## 3. Security検査

BFS nodeは左右state、logical slot、左右utility trackerからなる。各nodeで同一environment inputを左右へ適用し、observer projectionを比較する。

projectionは次を含む。

- release presence
- observerから見えるfield/value
- observerから見えるauthorized action emission

最初の差異を見つけた時点で、BFS predecessorから最短slot長のtraceを復元する。counterexampleにはobserver ID、slot、左右観測、最初のcausal field、入力trace、左右release、repair候補を含める。

## 4. Utility検査

各走について次を検査する。

- obligationへbindされていないactionを拒否する
- action ID、trigger、deadlineに合わないactionをunauthorizedとする
- 同じobligationの2回目の実行をduplicateとする
- authorized actionがdeadlineまでにちょうど1回実行されたことを確認する
- recoverable faultから生成されたobligationがdeadlineまでに実行されたことを確認する

utility違反もsecurity divergenceと同じ構造化counterexampleへ変換する。repair候補は修正の正しさを保証するものではなく、後続repair engineが探索を始めるための局所的hintである。

## 5. 決定順序

同一slotでは次の順で判定する。

1. observer trace divergence
2. 左走utility違反
3. 右走utility違反
4. 次product stateの探索

したがって同じslotに複数の違反がある場合、返る反例は上記priorityに従う。BFSはslot長について最短だが、同一slot内のすべての反例を列挙しない。

## 6. Resource exhaustion

`CheckOutcome`は次の3状態を区別する。

- `Verified`: 宣言された有限horizonを全探索した
- `Counterexample`: 具体的な最短反例を発見した
- `Inconclusive`: node、depth、timeのいずれかの上限へ到達した

`Inconclusive`を安全性証明または充足不能判定として扱ってはならない。CLIとartifactはこの3値を保持しなければならない。

## 7. 保証範囲

`Verified`が保証するのは、入力model、observer projection、initial pair、environment alphabet、horizonの範囲内だけである。

次は保証しない。

- 無限traceのsecurity
- modelへ含まれないobserverまたはside channel
- frontend DSLからchecker modelへのloweringの正しさ
- hardware timing、BLE radio、OS schedulingの実測挙動
- solverが提示する最適性
- repair候補を適用した後の正しさ

証明書checker、synthesis、repair、code generation、Noticer adapterは後続Issueで追加する。
