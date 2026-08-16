# QuotientForge Exhaustive and CEGIS Synthesis

## 1. 目的

`quotient-forge-synth`は、small finite model向けのsolver非依存AQRS synthesis backendである。外部SAT/SMT solverを使わず、release machineを完全列挙し、K6-04 product checkerだけをsecurity oracleとして利用する。

このbackendの目的は大規模性能ではなく、後続solver backendと比較できる再現可能なreference semanticsを固定することである。

## 2. Synthesis problem

入力はprivate plantとrelease machineを分離する。

- private plant stateはaction semantics IDとprivate history IDを保持する
- public/fault environment inputは左右走へ共通に与える
- plant transitionは次plant stateとmachine symbolを返す
- release machineはmachine stateとsymbolから次machine stateとoutput IDを返す
- output alphabetはK6-04の`Release`である
- observer、semantic obligation、fault obligation、initial private pairはK6-04 modelへそのままlowerする

candidate評価時には`plant state × machine state`をchecker stateへ展開する。private history IDはplantから複製するだけで、release machine stateへprivate biosignal値を格納しない。

## 3. Canonical enumeration

state boundは1から順に増加させる。各boundでtableを次のcanonical順序により列挙する。

1. initial machine stateを0へ固定する
2. table keyを`(machine state, symbol)`辞書順へ固定する
3. destination stateの新規IDは最初の出現順にのみ導入する
4. state 0から到達不能なmachineを除外する
5. output列挙開始位置だけを単一seedから決定する

これによりstate renaming対称性を削減する。seedが同じならcandidate順序、counterexample順序、最終resultは同じになる。

## 4. CEGIS blocking clause

checkerがcounterexampleを返した場合、traceの左右走が実際に参照した`(machine state, symbol) -> (next state, output)` decisionを抽出する。

blocking clauseは、それらすべてのdecisionが同じcandidateを除外する。source candidate自身を除外できないclauseは内部errorとし、探索を継続しない。

clauseはtrace外のtable cellを拘束しない。このため単なるcandidate全体hashより強く、同じ失敗traceを再現する複数candidateをchecker呼び出し前に除外できる。

## 5. Feasibilityとoptimization

APIを分離する。

- `find_feasible`: 最小state boundで最初に検証成功したcandidateを返す
- `optimize_cost`: 最初に実現可能となったstate boundを全探索し、cost最小candidateを返す

costは次の辞書順vectorである。

1. machine state数
2. emitting table cell数
3. table cellが参照するfield valueのbyte数
4. action emission数

同一costではcanonical machine bytesをtie-breakerにする。より大きいstate boundは第1cost成分で必ず劣るため、最初の実現可能boundより先をoptimizationで探索しない。

## 6. Outcome

- `Realizable`: checkerが有限horizon全体を検証した実machineを含む
- `Unrealizable`: 指定した全state boundのcanonical candidateを完全探索した
- `Inconclusive`: candidate、time、checker resource、enumeration domain上限へ到達した

timeoutまたはresource exhaustionを`Unrealizable`として扱ってはならない。

## 7. 保証境界

このbackendが保証するのは、宣言されたfinite plant、output alphabet、observer、utility/fault contract、horizon、state boundの範囲だけである。

次は保証しない。

- 無限trace
- DSLからsynthesis problemへのlowering
- exhaustive上限を超えるmodelのrealizability
- cost modelが実hardware消費を正確に表すこと
- solver backendのencodingまたは最適性
- hardware timing、BLE radio、OS scheduling

SMT-LIB/MaxSMT backend、repair、code generation、Noticer adapterは後続Issueで追加する。
