# QuotientForge Incremental CEGIS Session

## 位置づけ

K7-06cは、solver固有実装と独立した決定論的CEGIS lifecycleを定義する。目的はspeedupの主張ではなく、同じbounded problem、epoch、seed、blocker集合から同じdecisionと監査可能なtranscriptを得ることである。

## lifecycle

1. `SessionContext`がK7-06bのproblem hash、epoch、seedを固定する。
2. `SessionBlocker`がtyped blocker artifact、source candidate、counterexample signature、backend assertionをSHA-256参照で結ぶ。
3. 初期blockerはclass、counterexample signature、assertion、blocker digestの順でcanonical化する。
4. backend generation開始時はcanonical順で全blockerをreplayする。
5. candidateは独立checkerへ渡し、verified、rejected、inconclusiveを区別する。
6. rejected candidateのblockerがsource candidateへ結び付かない場合はfail closedする。
7. 一定数のaccepted blocker、またはcanonical順を保てない追加で決定論的restartを行う。

## blocker抑止

- 同じ`blocker_sha256`はduplicateとして追加しない。
- 既存blockerが明示的にsubsumesするblockerは追加しない。
- 新blockerが既存blockerをsubsumesする場合、canonical集合から既存blockerを除き、backendをrestartして集合全体をreplayする。
- subsumption参照はK7-06aの保守的な関係から作る。session自身が未知の論理的含意を推測することはない。

## fail-closed境界

次の状態を`UNSAT`へ変換してはならない。

- timeout
- resource exhaustion
- solver unavailable
- process spawn、exit、protocol failure
- checker inconclusive
- candidate limit
- 不正またはsource不一致のblocker
- duplicate/subsumed blockerしか返らず進展できない状態

これらは理由付き`INCONCLUSIVE`としてartifactに残す。`UNSAT`はbackendがbounded problemに対して明示的に返した場合だけ記録する。

## artifactと監査

`quotient_forge_incremental_cegis_session_v1.schema.json`は次を保存する。

- bounded problem hash、epoch、seed、restart policy
- canonical blocker集合
- generation付きsession transcript
- candidate、checker call、blocker push、restartの計数
- replay push、incremental push、同一generation内solve再利用の計数
- 最終decisionとcanonical artifact digest

wall-clock時刻やprocess固有メッセージはtranscriptへ含めない。これにより同じ入力とseedのartifactをbyte-levelで比較できる。

## 検証範囲

fake incremental backendを用いて、同一入力のtranscript再現性、restart前後のbounded decision同値性、canonical replay、duplicate/subsumption抑止、失敗状態の非UNSAT性をテストする。実solverの性能比較とspeedup評価はK7-06eで行い、改善を前提にしない。
