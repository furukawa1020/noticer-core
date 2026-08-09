# Atypicality Token v2 Formal Specification

> **A token generated from atypicality, not a token containing atypicality.**

Status: K0 Working Specification  
Last Updated: 2026-08-09

---

## 1. Purpose

この文書は、Noticer CoreにおけるAtypicality Token v2を、
**Claim-Quotient Atypicality Token (CQ-AT)**として定義する。

Atypicality Tokenは本人内変化の値や表現ではない。
本人内変化についての私的な逐次証拠がpolicy条件を満たしたとき、
限定されたactionだけを許可する短命なauthorityである。

本仕様は次を固定する。

1. private evidence
2. allowed declassification
3. public capability
4. release trace
5. Pufferfish secret pairs
6. composition rule
7. poisoning model
8. formal invariants

暗号envelope、BLE、Foundation Model、実PPG adapterは後続K1以降で実装する。

---

## 2. Core Boundary

旧モデル:

```text
PPG
→ embedding
→ key-dependent transformation
→ transformed atypicality representation
```

v2モデル:

```text
PPG
→ private evidence process
→ policy decision
→ action authority
→ independently randomized capability token
```

公開objectは生理状態のdescriptionではなく、action authorityである。

```text
High Side                        Low Side

raw signal                      action symbol
private representation          bounded authority
personal baseline       ─D─>     randomized token envelope
nonconformity score              shaped release trace
p-value / e-value
```

`D`だけがdeclassification boundaryを越えられる。

---

## 3. Terminology

### Private History

時刻`t`までのhigh-side objectを`H_t`とする。

```text
H_t = {
  raw observations,
  private representations,
  contexts,
  baseline state,
  nonconformity scores,
  p-values,
  e-process state,
  quality state,
  quarantine state
}
```

### Allowed Claim

本人がpolicyで許可した低主張な意味範囲を`C_t`とする。
v2の第一対象は`ChangeCue`以下である。

### Authorized Action

外部へdeclassifyできる有限個のaction symbolを`a_t`とする。

```text
NoAction
MenfuguInflateSoft
RenderAmbientPulse
RenderReviewPrompt
```

### Atypicality Token

`a_t`をaudience、policy、epoch、有効期間、利用回数へ束縛したpublic capabilityを`AT_t`とする。

### Release Trace

攻撃者が観測できるtoken contentとtransport metadataの時系列全体を`R_1:T`とする。

---

## 4. Private Atypicality Evidence

private feature extractorを`E`、contextを`c_t`とする。

```text
h_t = E(x_t)
s_t = d(h_t, B_u(c_t))
```

- `x_t`: current private physiological window
- `h_t`: private representation
- `B_u(c_t)`: user- and context-conditioned baseline
- `s_t`: private nonconformity score

`h_t`、`B_u(c_t)`、`s_t`はいずれもpublic API objectにしてはならない。

### 4.1 Conformal p-value

baseline calibration scoresを用いる場合、候補p-valueを次で定義する。

```text
p_t = (1 + Σ_i 1[s_i >= s_t]) / (|B_u(c_t)| + 1)
```

tie handling、calibration期間、context不足時のfallbackは実装前に固定する。

### 4.2 Sequential evidence

単一windowでは発行しない。betting function`g`を用いる候補e-processを、

```text
E_0 = 1
E_t = E_(t-1) * g(p_t)
```

とし、

```text
issue_candidate_t iff E_t >= tau_alpha
```

とする。

### 4.3 Statistical assumptions

`anytime-valid`やfalse-release controlは無条件には主張しない。
最低限、次を実験ごとに明示する。

- exchangeabilityまたは採用する代替仮定
- calibration dataとmonitoring dataの依存
- context selectionの方法
- drift adaptationがvalidityへ与える影響
- optional stoppingに対する保証範囲
- repeated users / servicesに対する多重性

仮定が成立しない場合、e-processはengineering scoreとして扱い、
理論保証を主張しない。

---

## 5. Context-Conditioned Personal Baseline

baselineは二層に分離する。

### Anchor Baseline

`B^A_(u,c)`は明示的calibrationから作る。

- versioned
- rollback可能
- 自動で大幅更新しない
- provenanceを保持する
- adaptive baselineの逸脱検査基準になる

### Adaptive Baseline

`B^D_(u,c,t)`は長期driftへ限定的に追従する。

```text
B^D_(t+1) = RobustUpdate(B^D_t, h_t)
```

ただし更新は次をすべて満たす場合だけ許可する。

```text
quality sufficient
and no active evidence alert
and outside quarantine window
and influence <= configured bound
and update budget remains
and anchor divergence <= configured bound
```

### Poisoning security interpretation

baseline更新は単なるmodel adaptationではない。
将来のaction authority発行条件を変更するsecurity-sensitive operationである。

攻撃者の目的は次を含む。

- abnormal patternをusualへ吸収する
- usual patternを異常化する
- token floodingを起こす
- token suppressionを起こす
- contextを偽装して別baselineを選ばせる
- update budgetを枯渇させる

すべてのbaseline updateは、version、理由、bounded influence、rollback pointを監査可能にする。
raw representation自体はauditへ保存しない。

---

## 6. Allowed Declassification

declassification functionを次の型として固定する。

```text
D : PrivateHistory × Policy → AuthorizedAction
```

```text
D(H_t, P) = a_t
```

`D`のcodomainは登録済みaction symbolだけである。
score、p-value、e-value、confidence、原因、identityを返すvariantを追加してはならない。

### 6.1 Decision preconditions

action候補は最低限、次をすべて満たす場合だけ生成できる。

- evidence threshold satisfied
- signal quality policy satisfied
- baseline state valid
- no rollback or arithmetic violation
- action is permitted by Claim Cap
- cooldown satisfied
- release budget available
- privacy odometer permits release
- service authorization active

不明または矛盾する状態は`NoAction`へfail closedする。

### 6.2 Action-only boundary

action symbolへ次を付随させてはならない。

```text
exact score
p-value
e-value
confidence
raw timestamp
feature identifier
context label
event cause
baseline distance
```

---

## 7. Public Atypicality Token

概念的なtokenを次で表す。

```text
AT_t = Sign_K_e(
  protocol_version,
  pairwise_audience_binding,
  authorized_action,
  policy_hash,
  epoch,
  not_before,
  expiry,
  max_uses,
  sequence_or_nonce,
  proof_of_possession_binding
)
```

### Included fields

- protocol version
- pairwise opaque audience binding
- authorized action
- policy hash
- key epoch
- coarse not-before / expiry
- bounded use count
- independently generated nonce
- proof-of-possession binding where required
- standard authentication tag or signature

### Forbidden fields

- raw PPG / IBI / ACC
- embedding or feature vector
- exact or quantized atypicality score
- baseline distance or statistics
- p-value / e-value
- confidence
- stress, valence, arousal, diagnosis
- global user identifier
- demographic attribute
- exact physiological timestamp

### Content noninterference target

同じaction、policy、epoch、authority parametersの下では、token body generationは
private evidenceの大きさや形態を入力に取らない。

```text
AT_t ⟂ {x_t, h_t, s_t, p_t, E_t, B_u}
      | {a_t, P, epoch, authority_parameters}
```

これは観測trace全体のunlinkabilityを意味しない。
token発行の有無と時刻は別のrelease surfaceである。

---

## 8. Release Trace

攻撃者の観測を次で定義する。

```text
R_1:T = {
  token bytes,
  packet time,
  packet size,
  silence,
  failure behavior,
  action sequence,
  reconnect behavior,
  service-local epoch events
}_1:T
```

token bodyが安全でも、`R_1:T`からidentity、routine、attribute、状態、
cross-service linkageが推定され得る。

### 8.1 Claim-conditioned excess leakage

allowed action sequenceを`C_1:T`、secretを`S`、攻撃器を`A`とする。

```text
Delta_A = Perf(A(R_1:T, C_1:T)) - Perf(A(C_1:T))
```

評価対象は、allowed actionを知ることで不可避な漏えいではなく、
token content、timing、metadataが与える追加漏えいである。

`Perf`はsecretに応じてaccuracy、balanced accuracy、AUC、EER、
linkability advantage等から事前登録する。

---

## 9. Pufferfish Secret Pairs

Claim-Conditioned Release Privacyを、biosignal-derived action-token streamに対する
Pufferfish / Blowfish policyの具体化として扱う。

### Secrets

候補secret familyは次を含む。

- identity
- demographic / physiological attribute
- waveform morphology
- semantic state not authorized by policy
- daily routine beyond allowed actions
- cross-service identity correspondence
- baseline membership or update history

### Discriminative pairs

private histories`H`と`H'`について、

```text
H ~_C H'
```

を、同じallowed action sequence`C`を持つが、保護対象secretだけが異なる二世界とする。

### Privacy target

release mechanism`M`とobservable trace event`O`について、

```text
Pr[M(H) in O] <= exp(epsilon) Pr[M(H') in O] + delta
```

を目標とする。

この保証を主張するには、secret pairs、data-generation model、攻撃者知識、
time horizon、隣接関係、composition条件を具体的に固定しなければならない。

一般的な新privacy frameworkとは主張しない。

---

## 10. Composition and Privacy Odometer

単発tokenの性質を長期traceへ自動的に拡張してはならない。
serviceごとにprivacy odometer stateを持つ。

```text
OdometerState {
  release_count
  remaining_release_budget
  horizon
  recent_action_histogram
  timing_leakage_estimate
  cross_service_correlation_risk
  user_burden
  last_authorization_epoch
}
```

### Composition rule

各release候補`r_t`に対して、

```text
allow(r_t) iff
  policy_budget_available
  and privacy_budget_available
  and trace_risk_after(r_t) <= configured_bound
```

を満たさない場合、次のいずれかをpolicyに従って選ぶ。

- delay
- batch
- suppress
- replace with cover traffic
- switch to local-only action
- require user re-authorization

epsilonの単純加算は、採用mechanismのcomposition theoremが適用できる場合だけ使う。
適用不能な場合はempirical odometerとして明示し、formal privacy budgetと呼ばない。

---

## 11. Trace Shaping

### Fixed-rate capability channel

observer-facing transportは候補として、一定間隔・固定長packetを送る。

```text
t0  fixed-size packet
t1  fixed-size packet
t2  fixed-size packet
...
```

packetはauthorized actionまたはcover packetを運ぶ。
外部observerが両者を区別できるmetadataを追加してはならない。

### Per-service independence

serviceごとに次を分離する。

- pairwise audience binding
- key epoch
- nonce stream
- release budget
- jitter schedule
- cover schedule
- odometer state

同じ物理actionそのものが公開される場合、その相関はallowed claimに含まれ得る。
完全unlinkabilityではなく、allowed action以上の追加linkabilityを評価する。

---

## 12. Attacker Model

最低限、次を扱う。

### Passive inference

- token content inference
- timing-only inference
- action-sequence inference
- identity / attribute inference
- cross-service linkage
- baseline membership inference

### Active attacks

- baseline poisoning
- context manipulation
- event flooding
- event suppression
- adaptive query timing
- service collusion
- replay / forgery / revocation bypass
- clock rollback
- cover-channel distinguishability probing

攻撃者は設計、policy family、model architecture、評価方法を知る。
secret keyとhigh-side private stateだけを知らない。

---

## 13. Formal Invariants

### INV-AT-1 — Evidence-conditioned issuance

```text
Issued(AT_t) → EvidencePolicySatisfied(H_t, P)
```

### INV-AT-2 — Action-only declassification

```text
D(H_t, P) ∈ RegisteredActionSymbols
```

### INV-AT-3 — No evidence in public content

```text
PublicFields(AT_t) ∩ PhysiologicalEvidenceFields = empty
```

### INV-AT-4 — Conditional content independence

同じpublic authority parametersの下で、token encoding APIはprivate evidenceを引数に取らない。

### INV-AT-5 — Claim boundedness

```text
RequiredClaim(action) <= PolicyClaimCeiling
```

### INV-AT-6 — Bounded authority

```text
Accepted(AT_t) →
  AudienceMatches
  and CurrentEpoch
  and WithinValidity
  and UsesRemaining
  and PolicyAuthorized
```

### INV-AT-7 — Atomic use

```text
max_uses = 1 → at most one privileged acceptance
```

### INV-AT-8 — Monotonic private time

logical time rollback cannot produce evidence, baseline update, or authority.

### INV-AT-9 — Guarded baseline update

```text
BaselineUpdated → UpdateGateSatisfied
```

### INV-AT-10 — Bounded evidence memory

evidence、quarantine、budget stateは設定horizonを超えて無制限に増えない。

### INV-AT-11 — Trace accounting

各real release候補は、発行・delay・batch・suppressの決定前にodometerへ入力される。

### INV-AT-12 — Fail closed

```text
VerificationFailure or InvalidPrivateState → NoPrivilegedAction
```

### INV-AT-13 — Sanitized audit

audit recordはpolicy/decision/token identifierを追跡できるが、raw signal、embedding、score、
p-value、e-value、baseline、identityを含まない。

### INV-AT-14 — No automatic longitudinal claim

single-release securityからtrace privacyを推論しない。長期主張はcomposition評価に依存する。

---

## 14. Required Type and API Separation

将来実装では、最低限次のmodule境界を守る。

```text
high_side/
  ObservationFrame
  PrivateRepresentation
  BaselineState
  NonconformityScore
  ConformalPValue
  EvidenceState

declassifier/
  evaluate_evidence(private_state, policy) -> AuthorizedAction

low_side/
  AuthorizedAction
  AtypicalityTokenBody
  ReleasePacket
  ReleaseTraceMetadata
```

high-side型はserialization traitを実装しない。
low-side encoderはhigh-side型を受け取れない。
token issuerが受け取れるprivate側の値は`AuthorizedAction`だけとする。

---

## 15. Evaluation Obligations

### Evidence validity

- empirical false-release rate
- detection delay
- exchangeability violation sensitivity
- context scarcity
- drift and adaptation sensitivity
- calibration horizon sensitivity

### Poisoning robustness

- attack budget versus baseline displacement
- flooding / suppression success
- quarantine effectiveness
- recovery time
- anchor rollback utility

### Content leakage

- identity / attribute / morphology inference from token fields
- field ablation
- conditional-excess leakage over allowed action
- malformed and optional metadata leakage

### Trace leakage

- timing-only attacker
- frequency / silence attacker
- multi-service collusion
- cover distinguishability
- fixed-rate overhead and action latency
- longitudinal composition

### Authority enforcement

- valid use
- replay / concurrent double use
- wrong audience
- expiry / epoch / revocation
- Claim Cap bypass
- fail-closed behavior

---

## 16. Falsification Conditions

次のいずれかが成立した場合、主張を縮小または設計を変更する。

- e-process保証に必要な仮定がdeploymentで成立しない
- action-only codomainでもtoken traceから大きな追加漏えいが生じる
- cover trafficが実用上許容できないoverheadを要求する
- privacy odometerに根拠あるcomposition ruleを与えられない
- adaptive baselineが現実的な攻撃budgetでpoisonされる
- Atypicality Tokenが既存ReleasePacketと実質的に同一になる
- capability envelopeの標準機能が主要貢献の過半を占める
- Menfugu統合がsecurity semanticsを検証しない単なるdemoになる

失敗結果を隠して完全privacy、unlinkability、anytime validityを主張しない。

---

## 17. Novelty Boundary

新規性として単独では主張しない。

- within-person atypicality
- low-cardinality token
- raw PPG non-egress
- Claim Cap concept
- identity / reconstruction attack
- Ed25519, expiry, replay, revocation
- service-scoped keying
- traffic shapingそのもの
- conformal detectionそのもの

中心候補は次の統合境界である。

1. private sequential evidenceからaction authorityへのdeclassification
2. public token contentのconditional noninterference
3. allowed actionに条件づけたlongitudinal trace privacy
4. repeated release compositionとprivacy odometer
5. authority発行を守るpoisoning-resistant personal baseline

---

## 18. Implementation Sequence

```text
K0  Atypicality Token v2 formal specification

K1  Private Atypicality Evidence Process
    context baseline / conformal p-value / e-process
    anchor-adaptive baseline / poisoning guard

K2  Claim-Quotient Security Core
    EvidencePermit -> ActionClaim one-way quotient
    Low Side type boundary / matched-claim trace simulator / TNMC smoke game

K3  Standard-Based Capability Envelope
    expiry / proof of possession / replay / revocation

K4  Fixed-Rate BLE Channel and Menfugu Verifier

K5  Attack Observatory

K6  Real PPG and Foundation Model Integration
```

K1以降の実装は、本仕様のinvariantとevaluation obligationへ追跡可能でなければならない。

---

## 19. Research Claim

> **Noticer Core irreversibly quotients private sequential evidence of within-person change
> into an explicitly authorized action claim, then mints bounded capabilities whose full
> observable trace has no information dependency beyond that claim.**

`anytime-valid`はK1で仮定と実証が成立した場合だけ使用する。
成立前の安全な表現は`sequential evidence-conditioned`とする。

---

## 20. Reference Foundations

本仕様は、既存のconformal/e-process、Pufferfish/Blowfish、capability authorization、
information-flow control、traffic shapingを基礎として利用する。
それらの一般理論をNoticer Coreの新規発明とはしない。

主要な研究差分は、これらをbiosignal-derived action-token streamの単一境界へ接続し、
allowed actionを維持したままcontent、trace、composition、poisoningを一緒に評価する点に置く。
