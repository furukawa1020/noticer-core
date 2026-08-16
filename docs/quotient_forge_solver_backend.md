# QuotientForge Canonical SMT-LIB and Solver Backend

## 1. 目的

`quotient-forge-solver`は、AQRS candidate transducerを提案する外部solverとの境界をcanonical SMT-LIB 2.6で固定する。

solverはsecurity proofを発行しない。solver modelはcandidateにすぎず、K6-04 product checkerの有限全探索を通過した場合だけ`SAT` resultとして返す。

## 2. Backend選択

選択肢は明示的に分離する。

- `Auto`: `cvc5`、`z3`の順でversion probeする
- `Explicit(Cvc5)`: cvc5だけを使い、未導入時はfallbackしない
- `Explicit(Z3)`: z3だけを使い、未導入時はfallbackしない
- `Explicit(Exhaustive)`: K6-06 reference backendを使う

`Auto`で外部solverが1つもない場合、`state_bound × machine_symbol_count`が設定閾値以下のsmall modelだけをK6-06へfallbackする。閾値を超える場合は`NOT_INSTALLED`を返す。

artifactはprobe順、program名、available、versionまたはerror、選択solver、選択versionを保持する。

## 3. Canonical SMT-LIB

各table cell `(machine_state, symbol)`について次の整数変数を宣言する。

- `n_<state>_<symbol>`: 次machine state
- `o_<state>_<symbol>`: output ID

scriptは常に同じ宣言順、range constraint順、symmetry constraint順、blocker順、objective順で生成する。

hard structural constraintは次を含む。

- next/output range
- state 0を暗黙initial stateとする固定
- 各stateがより小さいIDのstateから参照されるreachability
- 新state IDのfirst-use ordering

## 4. Checker-backed CEGIS

Phase Aでは構造constraintと既知counterexample blockerだけをhard assertionにする。solverが`SAT` modelを返したら実machineへdecodeし、K6-04 checkerへ渡す。

checker反例はK6-06と同じtrace-based blocking clauseへ変換し、種類ごとに次のnamed hard assertionとして追加する。

- `hard_security_*`
- `hard_utility_*`
- `hard_fault_*`

blockerがsource candidateを除外しない場合はsolver outputを不正として停止する。反例をsoft objectiveへ変換してはならない。

## 5. Phase分離

Phase Aはsecurity/utility/fault feasibilityだけを扱い、`minimize`を含まない。

最初のchecker-verified candidateを得た後だけPhase Bへ移る。Phase Bは同じhard constraintを保持し、次をlexicographic順に最適化する。

1. dummy
2. latency
3. state
4. retry
5. reconnect

Phase Bのcandidateも独立checkerへ戻す。最適化solverの成功応答だけでは受理しない。

## 6. Output parser

parserはS-expressionを構文解析し、期待した全`n_*`/`o_*`定義が一度ずつ整数として存在することを要求する。

次を別statusとして保持する。

- `SAT`
- `UNSAT`
- `TIMEOUT`
- `MALFORMED_OUTPUT`
- `NOT_INSTALLED`
- `RESOURCE_EXHAUSTED`

missing definition、duplicate definition、非整数、unbalanced parenthesis、未知status、範囲外model、canonical symmetry違反は`MALFORMED_OUTPUT`である。timeoutを`UNSAT`へ変換してはならない。

## 7. Process境界

標準runtimeはshellを介さず直接processを起動する。

- cvc5: `cvc5 --lang=smt2 --produce-models`
- z3: `z3 -in -smt2`

SMT-LIBはstdin、modelはstdout、診断はstderrで受ける。deadline超過時はchild processを停止して`TIMEOUT`を返す。

testは外部binaryへ依存せず、fake runtimeでversion、SAT、UNSAT、timeout、malformed、not-installedを再現する。

## 8. 非保証事項

このbackendは次を保証しない。

- 外部solver自体の正しさ
- solverが報告するoptimality
- finite bound外のrealizability
- DSLからsynthesis problemへのlowering
- objective weightが実hardware costを正確に表すこと
- hardware timing、BLE radio、OS scheduling

最終security判定とcertificate検証はK6-04/K6-05の独立checker境界に残す。
