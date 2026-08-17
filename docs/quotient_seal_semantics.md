# QuotientSeal source / target / observer / context semantics

Status: **FROZEN v1**  
Machine-readable contract: `configs/quotient_seal/k8_semantics.yaml`  
Schema: `schemas/k8_raqtr_semantics.schema.json`

## 1. Purpose

この文書は、QuotientSealの中心候補security propertyであるRobust
Action-Quotient Trace Refinement（RAQTR）を実装へ落とす前に、source、target、
observer、adversarial contextの意味論を固定する。

ここで定義するのはrestricted WASMのparserや実行器ではない。K8-01は有限モデル上の
語彙、関係、停止理由、判定規則を固定する段階である。実命令意味論はK8-03とK8-04、
translation validationはK8-05で実装する。

## 2. K7 reference boundary

Source machineはK7でCAQT certificateに受理されたmachineへのopaque referenceである。
K8は次を再定義しない。

- CAQT certificate format
- K7 source-machine stateとtransition
- generated runtime manifestとharness

`SourceStateRef`が保持するのはcertificate digest、state ID、action-semantics IDだけである。
#77と#88がmainへ入るまでは、具体型へのbindingを作らない。

## 3. Worlds and source semantics

二つのworld `wL`、`wR`は次を満たすとき比較対象になる。

1. private-history digestが異なる。
2. K7が与えるaction-semantics IDが等しい。
3. public call列とpublic fault列が同じである。

同一private historyや異なるaction semanticsは反例ではなく、propertyの前提外として
`INCONCLUSIVE / PRECONDITION_NOT_MET`にする。前提外を`ACCEPT`へ変換しない。

Source observable alphabetは次だけである。

- `PUBLIC_CALL`
- `PUBLIC_RETURN`
- `AUTHORIZED_ACTION`
- `PUBLIC_FAULT`
- `TERMINATION`

private ingestの後もaction quotientが等しいことをprivate-ingest two-run equivalenceとする。
public callの後もsourceとtargetのaction quotientおよびpublic-state relationが保たれることを
public-call relational preservationとする。

## 4. Target state and event trace

Target stateは次の積である。

```text
T = ModuleDigest x PC x PublicStateDigest x PrivateHandle
    x MemoryPages x ExecutionStatus x ActionSemanticsId
```

`PrivateHandle`はopaque indexであり、context observationへ渡らない。K8-01の型では
private bytes、biosignal history、baselineをcontext transitionへ格納できない。

Target event alphabetはAPI、action、host call、trap、control、instruction、memory、
deterministic resource、termination、unknown failure、context commandを分離する。
`RESOURCE`はstep数、page数などmachine-definedな決定的量だけを表す。wall-clock時間は
`EMPIRICAL_ONLY`であり、resource-trace equivalenceの要素ではない。

## 5. Observer profiles

| ID | Surface |
|---|---|
| `O0` | API call、return、action |
| `O1` | O0とtrap、termination、unknown failure |
| `O2` | O1とcontrol event |
| `O3` | O2とinstruction-class event |
| `O4` | O2とmemory access / growth event |
| `O5` | O0-O4を結合し、host callとresourceを追加したservice observer |
| `O6` | context commandを含む全surfaceのcolluding observer |

各profileのprojectionはtarget traceから見えるeventだけを順序を保って抽出する。
O6は宣言済みevent alphabet全体を必ず見る。未宣言eventを黙って消してはならない。

## 6. Capability-scoped reactive context

Context automatonのtransition keyは次である。

```text
(ContextState, PublicObservation) -> (NextContextState, PublicCommand)
```

許されるcommandは`PUBLIC_CALL`、`PUBLIC_FAULT`、`PUBLIC_RESET`、
`PUBLIC_HANDOFF`、`STOP`だけである。`PRIVATE_INGEST`、private-history read、
private-state read、linear-memory readはcontext capabilityではない。

同一keyに二つのtransitionを定義したautomatonは非決定的としてconstruction時にrejectする。
左右のobservationが等しいとき、context transitionは一度だけ選ばれ、その同じcommandを
両worldへ供給する。observationが異なる場合は、その時点でprivacy counterexampleである。

## 7. Partial abstraction and trace refinement

Partial abstraction `alpha : TargetEvent -> SourceEvent option`は次の規則を持つ。

- API call / return、action、terminationはsource eventへ直接写す。
- control、instruction、memory access、resource、context commandはsource側ではsilent。
- allowlist内のhost callだけをsilentにできる。
- 宣言済みtrapだけを対応する`PUBLIC_FAULT`へ写せる。
- unknown host call、target-only trap、memory growth、unknown failureはfailureである。

Target trace全体を抽象化した列はsource trace全体と完全一致しなければならない。したがって
extra host call、追加action、target-only trap、target-only memory growth、unknown failureを
成功扱いできない。

## 8. Utility preservation

Privacyだけを満たすsuppress-all implementationをrejectするため、各runにutility obligationを
付ける。各obligationは次を要求する。

- authorized actionだけを出す。
- obligation IDごとにexactly onceで出す。
- earliest slotからdeadline slotまでに出す。
- 宣言済みrecoverable faultにはrecovery actionを出す。

未認可、重複、期限外、欠落、recovery欠落はすべて`UTILITY_FAILURE`である。

## 9. RAQTR finite judgment

一つのobserver `Oi`に対する有限判定は次の順に行う。

1. private-distinct / action-equivalent preconditionを確認する。
2. resource・parser・unsupported境界を確認する。
3. source two-run trace equalityを確認する。
4. 左右それぞれのsource-target trace refinementを確認する。
5. 左右それぞれのutilityを確認する。
6. `Oi`のtarget projection equalityを確認する。
7. 同一observation後のcontext couplingを確認する。

全条件を満たした有限productだけが`ACCEPT`になる。`ACCEPT`、`COUNTEREXAMPLE`、
`INCONCLUSIVE`は排反である。

## 10. Termination and resource outcomes

`NORMAL_RETURN`、宣言済み`TRAP`、`TERMINATION`はtraceとして比較する。
fuel exhaustion、state-bound exhaustion、unsupported instruction、unknown import、
parser disagreementは`INCONCLUSIVE`であり、security successではない。

step budget内でcycleを検出した`BOUNDED_NONTERMINATION`は有限prefixとして観測できるが、
それだけでは任意長保証にならない。次の帰納条件をすべて満たす必要がある。

- base case
- step closure
- source determinism
- target determinism
- context determinism
- finite state space
- resource progress

K8-01の`InductionObligations`はこの条件のmachine-checkable guardであり、定理証明そのものでは
ない。Lean preservation theoremはK8-09の対象である。

## 11. Verdicts and fail-closed rule

`ACCEPT`は全義務が成立した場合だけ返す。観測差、refinement差、utility差、context decoupling、
state relation差は`COUNTEREXAMPLE`である。探索資源不足やunsupported inputは
`INCONCLUSIVE`である。いずれも`ACCEPT`へ再分類しない。

## 12. Non-claims

この意味論はgeneral secure compilation、full abstraction、arbitrary Rust/WASM、malicious
runtime / OS、native code、JIT code、cache、branch predictor、speculation、power、EM、
physical hardwareを検証しない。world-firstや優先権も主張しない。

## 13. Amendment rule

event alphabet、observer surface、capability、abstraction、verdict分類、resource分類、utility、
帰納条件を変える場合は`contract_version`と`schema_version`を上げ、v1を上書きしない。
実験結果を見た後にv1のfailureをsuccessへ緩和してはならない。
