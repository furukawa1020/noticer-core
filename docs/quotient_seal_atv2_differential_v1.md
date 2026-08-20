# ATv2 QSM Differential Evaluation v1

## 目的

この文書はIssue #171で実装する、ATv2公開source expectation、QuotientSeal small-step、wasmi、Wasmtimeの差分評価契約を固定する。

評価対象はIssue #170で生成したP0 QSMである。同じ公開context command列、host tape、resource limitsを全participantへ与え、source-target refinementとengine間一致を別々に判定する。

本評価はhardware equivalence、P1 sealed admission equivalence、transport adversaryへのrobustnessを主張しない。hardware statusとP1 statusは`NOT_VERIFIED`である。

## Source-derived expectation

source expectationはWasm interpreterではない。ATv2 compilerが束縛した公開frame placementから、次を独立に導出する。

- qsm service alias
- absolute slot
- public bucketとbucket内slot
- sequence
- `COVER`または`ACTION`のframe kind
- action frameに対応する公開action code
- reset後のcursor
- handoffで返す公開cursor
- typed public failure

engine共通の`EmitFrame` eventだけではcover/action区分を表現できないため、artifactにはframe kind付きexpected frame列を別に保存する。action frameは`EmitAction`を伴うが、cover frameは伴わない。この区分を一つのobserver valueへ畳み込んではならない。

## 共有入力

全participantは次を共有する。

- module SHA-256とcanonical ABI SHA-256
- source digestとframe-plan digest
- canonical context command列
- import順序を固定したpublic host tape
- fuel、memory pages、host calls、timeoutの上限
- participantごとの実行binary SHA-256

engine binaryのdigestは64桁の小文字hexとしてartifactへ保存する。digestが不正な評価は開始しない。

## 比較軸

比較は順序付きtraceとして行い、最初の差を保存する。

- output: `EmitFrame`、`EmitAction`、`PublicFailure`
- public state: status probeのdigest
- return: API callとreturn value
- host import: import名、引数、公開outcome
- resetとhandoff
- terminationとtrap class

source expectation対small-stepをsource refinementとして評価し、small-step対wasmi/Wasmtimeをdifferential oracleとして評価する。どちらか一方だけの一致を全体MATCHへ昇格してはならない。

## Verdict

`MATCH`はsource refinementがMATCHで、かつ3 engine oracleがMATCHの場合だけである。

`COUNTEREXAMPLE`は実行済みparticipant間にobservable differenceがあり、最初のtyped differenceを保存できた場合である。

`UNRESOLVED`はparser disagreement、unsupported instruction、timeout、resource exhaustion、engine failure、source expectation unavailableを表す。これらをMATCHまたはsecurity successとして扱ってはならない。

## 再現artifact

artifactはcanonical JSONへ直列化し、同じ入力ではbyte-identicalでなければならない。artifactには次を含める。

- schema/evaluator version
- source、frame plan、sequence digest
- frame kind付きsource expectation
- source reference run
- small-step、wasmi、Wasmtimeの全participant run
- source refinement
- differential oracle
- first typed differenceまたはunresolved reason
- `hardware_status: NOT_VERIFIED`

## 非主張

この段階では次を主張しない。

- P1 equivalence
- hardware equivalence
- reconnect、loss、deadline adversaryに対するrobustness
- 文献・特許上の優先権またはworld-first

transport adversary評価はIssue #172で行う。
