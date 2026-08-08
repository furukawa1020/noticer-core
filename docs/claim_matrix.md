# Noticer Core Claim Matrix v0.1

> **前の論文を言い換えてもう一度出さない。**
>
> Noticer Coreの価値は、既存のClaim Cap / CAPEを
> 「概念・モデル」から「攻撃可能な実システム境界」へ進めることにある。

Status: Draft  
Last Updated: 2026-08-09

---

## 1. Purpose

この文書は、Noticer Coreと以下の既存・投稿済み研究との
知的貢献の境界を明示する。

1. Claim-Capped Biosignal Feedback
2. CAPE / Privacy-Calibrated Encoder
3. CAPE-PPG-CED
4. Minute-CAPE-CORE
5. Noticer Local / Menfugu
6. Noticer Core（本研究）

目的は以下である。

- 二重投稿・salami slicingを避ける
- 新規性を実装前から固定する
- 既存成果を正しくprior workとして扱う
- 査読時に「前の論文との違いは？」へ一文で回答できるようにする
- 実験の使い回しと、新しいevidenceを区別する

---

# 2. One-Sentence Boundary

## Previous Work

> **What information should be released?**

既存研究では主に、
生体信号からどの情報を公開可能なclaimとして残し、
どの情報を公開しないかを扱った。

## Noticer Core

> **Who is allowed to cause which release or action, when, for how long,
> under which policy, and what happens when that authority is attacked?**

Noticer Coreは、
その公開境界を実システム上で強制する
**least-privilege biosignal reference monitor**
として扱う。

---

# 3. Claim Inventory

## P1. Claim-Capped Biosignal Feedback

**Paper**

`Claim-Capped Biosignal Feedback for Privacy-Calibrated Self-Observation on Mobile and Wearable Devices`

### Already Claimed

以下はNoticer Coreの新規貢献として主張しない。

- within-person atypicalityを用いたself-observation
- stress labelをdeployment outputにしない設計
- observationとinterpretationの分離
- Privacy-Calibrated Encoder
- baseline-relative residualization
- representation bottleneck
- Claim Cap Layerという概念
- unsupported diagnostic / evaluative labelを禁止する考え方
- privacyとutilityのjoint evaluation

### Already Evaluated

- WESAD
- CASE
- SWELL-KW
- atypicality utility
- identity inferability
- reconstruction inferability
- membership inferability
- sanity checks

### Existing Core Claim

既存研究が支持する範囲は、

> low-claim self-observation cueを維持しながら、
> 明示的な攻撃モデル下でrepresentation-level leakageを低減し、
> unsupported diagnostic outputを防ぐことができる。

### Must Not Be Presented as New

Noticer Core論文で以下を新規性として単独で書かない。

- 「ストレスと断定しない」
- 「本人内変化を見る」
- 「Claim Capを導入した」
- 「identity leakageを評価した」
- 「raw dataではなくprivacy-aware representationを使う」

### Legitimate Reuse

- motivation
- terminology
- Claim Cap philosophy
- within-person atypicality as an allowed utility
- previously published baselines
- comparison results, if clearly cited as prior work

### Required New Evidence

Noticer Coreでは、
Claim Capを単なるoutput designではなく
**runtime-enforced authority boundary**
として新たに評価する必要がある。

---

## P2. CAPE / Privacy-Calibrated Encoder

### Already Claimed

- privacy-sensitive informationとutilityを分離する表現
- identity suppression
- representation-level privacy / utility trade-off
- local personalization
- allowed utilityとforbidden inferenceの区別

### Must Not Be Presented as New

- adversarial representation learningそのもの
- identity-suppressed embeddingそのもの
- privacy–utility objectiveそのもの
- PCAE / CAPEというencoder思想そのもの

### Role in Noticer Core

CAPEはNoticer Coreの**内部実装候補**であり、
Noticer Coreそのものではない。

```text
CAPE
   ↓
private internal representation
   ↓
Noticer Core policy / authority / token layer
   ↓
bounded external capability
```

Noticer Coreの新規性をencoder性能へ依存させない。

---

# 4. P3. CAPE-PPG-CED

**Paper**

`CAPE-PPG-CED: Claim-Lattice Encoding of Real-Time PPG Streams
for Secure Biosignal Declassification`

これはNoticer Coreとの重複リスクが最も高いprior workである。

---

## Already Claimed

以下はCAPE-PPG-CEDですでに主張済みと扱う。

### Release Model

* biosignal latentをshareしない
* low-cardinality public claim tokenをreleaseする
* raw PPGをlocalに保持する
* private pulse codesをlocalに保持する
* personal baselineをlocalに保持する
* continuous latentをlocalに保持する
* exact atypicality scoreをlocalに保持する

### Architecture

* pulse-phase canonicalization
* private pulse codebook
* public claim lattice
* release gate
* ReleasePacket

### Security Framing

* PPG feedbackをdeclassification問題として扱う
* high-confidentiality objectとreleased objectを分離する
* forbidden claimをpublic codomainから除外する
* conditional-excess leakageを評価する

### Attacks / Evaluation

* identity inference
* waveform reconstruction
* membership inference
* affective attribute inference
* session linkability
* unsafe egress
* streaming latency
* privacy / utility comparison

### Core Concept

> 「latentを安全に共有する」のではなく、
> 「latentをそもそも共有する必要をなくす」

という発想。

---

## Must Not Be Presented as New

Noticer Coreで以下を新規貢献として単独で主張してはならない。

* claim-bounded declassification
* ReleasePacket
* claim lattice
* low-cardinality public output
* continuous latent non-release
* exact score non-release
* raw PPG non-egress
* release-level identity attack
* release-level reconstruction attack
* membership attack
* affective attribute attack
* sequence/session linkability evaluation

---

## What CAPE-PPG-CED Does NOT Establish

以下はNoticer Coreが新しく踏み込める候補である。

* cryptographic capability semantics
* service-scoped authority
* epoch-scoped authority
* capability expiration
* capability revocation
* cryptographic authenticity
* replay resistance
* token forgery resistance
* cross-service token reuse prevention
* explicit application authorization
* real OS-level reference monitor
* hardware-backed key integration
* compromised / malicious client behavior
* runtime policy enforcement
* actionable Claim Cap enforcement
* end-to-end actuator authorization
* timing side-channel defenses
* release shaping
* active baseline poisoning
* event flooding / suppression
* real BLE adversarial path
* fail-closed behavior
* recovery after attack
* multi-component end-to-end system evaluation

これらは**実装・評価して初めて新規貢献になる**。

---

# 5. P4. Minute-CAPE-CORE

## Existing Idea

Minute-CAPEは主として、

> **「何を出すか」だけでなく「いつ返すか」**

という時間的なrelease設計を扱う。

### Already Existing / Reserved

* notification timing
* temporal aggregation
* minute-scale release
* timing-based feedback control
* event cadence as a design object

### Overlap Risk

Noticer Coreでrelease shapingを扱う際に、

> timingを扱うこと自体

を新規性にしてはならない。

### Possible New Boundary

Noticer Coreではtimingを

> **UX上のnotification timing**

ではなく

> **security side-channel / traffic-analysis surface**

として扱う。

例:

* cross-service timing linkage
* event timing leakage
* padding
* jitter
* batching
* cooldown
* rate limiting

つまり、

```text
Minute-CAPE:
When should feedback occur for useful self-observation?

Noticer Core:
What timing information may an adversary observe,
and how should release timing be shaped to limit leakage?
```

として分離する。

---

# 6. P5. Noticer Local / Menfugu

## Already Existing

* non-diagnostic self-observation
* low-claim feedback
* physical externalization
* Menfugu inflation
* user-controlled use
* avoidance of manager-facing evaluation
* physical / nonverbal presentation of subtle change

### Must Not Be Presented as New

* 「ふぐを膨らませる」こと自体
* physical externalizationというアイデア
* non-diagnostic physical feedback
* Noticer Localというproduct concept

### Role in Noticer Core

Menfuguは、

> **Noticer Coreが出す最小のauthorityだけで、
> 実世界のactionが成立することを示す
> reference actuator**

として使う。

新規性はMenfugu本体ではなく、

```text
Unauthorized token → does not inflate
Expired token      → does not inflate
Replayed token     → does not inflate
Wrong service      → does not inflate
Valid capability   → inflates
```

という**security semanticsが物理世界まで保たれること**に置く。

---

# 7. P6. Atypicality Token

Mirai Next構想ではすでに、

* 本人内変化を表すtoken
* 端末・サービス鍵への依存
* 鍵更新
* token間の照合抑制
* identity / attribute / reconstruction / linkabilityを抑える目的

が構想されている。

したがって、

> 「鍵でAtypicality Tokenを作る」

だけではNoticer Coreの研究的新規性として不十分である。

---

## Atypicality Token → Atypicality Capability

Noticer Coreでは概念をさらに狭くする。

Tokenを、

> 情報を表現するデータ

としてではなく、

> **限定されたactionを実行する権限**

として扱う。

### Data-Oriented Token

```text
"This user is slightly atypical."
```

ではなく、

### Capability-Oriented Token

```text
"This verifier may execute ACTION_1
for SERVICE_X
until TIME_T
under POLICY_P
exactly once."
```

にする。

これをNoticer Coreにおける中心的な差分候補とする。

---

# 8. Noticer Core Candidate Novel Contributions

以下は**候補**であり、
実装・評価完了までは「新規貢献」と確定しない。

---

## N1. Biosignal Reference Monitor

生体信号releaseを、
モデルの出力問題ではなく、

> **OS / runtimeのauthority enforcement問題**

として扱う。

Noticer Coreがすべてのdeclassificationを仲介し、
アプリがraw PPG、latent、exact scoreへ直接アクセスできない構造を作る。

### Required Evidence

* architecture implementation
* API enforcement tests
* unauthorized access tests
* unsafe egress tests
* TCB measurement / description

---

## N2. Atypicality Capability

低主張なeventを単なるtokenではなく、
**action-scoped capability**として表現する。

Capabilityは最低限、

* service domain
* authorized action
* policy
* expiry
* sequence
* epoch
* nonce
* integrity protection

を持つ。

### Required Evidence

* valid capability acceptance
* expired capability rejection
* modified capability rejection
* wrong-service rejection
* cross-epoch rejection
* replay rejection

---

## N3. Cryptographic Domain Separation

service / device / epoch単位で権限を分離する。

### Security Question

> サービスA向けに得たcapabilityを、
> サービスBまたは別epochで再利用できるか？

### Required Evidence

* cross-service reuse attack
* cross-epoch reuse attack
* key rotation test
* revocation test
* compromise blast-radius analysis

---

## N4. Temporal Leakage Control

出力値だけではなく、
**出力がいつ発生したか**をsecurity surfaceとして扱う。

### Candidate Defenses

* coarse time buckets
* batching
* independent service jitter
* cooldown
* rate limiting
* constant / padded traffic where appropriate

### Required Evidence

* timing-only inference
* timing-only linkage
* colluding-service timing attack
* utility impact of shaping

---

## N5. Runtime Claim Enforcement

Claim Capを文章設計ではなく、
runtime policyとして強制する。

```text
Request:
"Display: You are stressed"

↓

Claim Monitor

↓

DENIED
```

### Required Evidence

* forbidden vocabulary tests
* forbidden action tests
* unauthorized recipient tests
* policy mutation tests
* bypass attempts
* fail-closed behavior

---

## N6. End-to-End Physical Authorization

Capability boundaryを
実際のBLE / firmware / Menfuguまで維持する。

```text
PPG
 ↓
Noticer Core
 ↓
Capability
 ↓
BLE
 ↓
Menfugu verifier
 ↓
Physical actuation
```

### Required Evidence

* packet capture
* tamper attack
* replay attack
* BLE disconnect / reconnect
* invalid token
* expired token
* valid token
* firmware verification failure

---

## N7. Active Attack Robustness

既存研究の主なpassive inference評価に加え、
active attackerを扱う。

### Attacks

* baseline poisoning
* event flooding
* event suppression
* adaptive queries
* invalid-token flooding
* service collusion

### Required Evidence

* attack success threshold
* utility degradation
* recovery behavior
* recovery time
* false event rate

---

# 9. Claim Matrix

| Contribution / Property        | Claim-Capped | CAPE-PPG-CED | Minute-CAPE | Noticer / Menfugu |              Noticer Core |
| ------------------------------ | -----------: | -----------: | ----------: | ----------------: | ------------------------: |
| Within-person atypicality      |            ✅ |            ✅ |           ✅ |                 ✅ |                Prior work |
| Non-diagnostic output          |            ✅ |            ✅ |           ✅ |                 ✅ |                Prior work |
| Claim Cap concept              |            ✅ |            ✅ |           — |                 ✅ |                Prior work |
| Privacy encoder                |            ✅ |            ✅ |           — |                 — |        Internal component |
| Raw PPG non-egress             |      Partial |            ✅ |           — |     Local concept |                Prior work |
| Continuous latent non-release  |            — |            ✅ |           — |                 — |                Prior work |
| Low-cardinality claim release  |            — |            ✅ |           — |                 — |                Prior work |
| ReleasePacket                  |            — |            ✅ |           — |                 — |                Prior work |
| Conditional-excess leakage     |            — |            ✅ |           — |                 — |                Prior work |
| Identity attack                |            ✅ |            ✅ |           — |                 — |               Extend only |
| Reconstruction attack          |            ✅ |            ✅ |           — |                 — |               Extend only |
| Membership attack              |            ✅ |            ✅ |           — |                 — |               Extend only |
| Attribute inference            |            — |            ✅ |           — |                 — |               Extend only |
| Sequence/session linkability   |            — |            ✅ |           — |                 — |               Extend only |
| Notification timing            |            — |     Non-goal |           ✅ |                 ✅ | Security reinterpretation |
| Physical externalization       |            — |            — |           — |                 ✅ |        Reference app only |
| Service-scoped authority       |            — |            — |           — |                 — |              🆕 Candidate |
| Epoch-scoped authority         |            — |            — |           — |                 — |              🆕 Candidate |
| Action capability semantics    |            — |            — |           — |                 — |              🆕 Candidate |
| Hardware-backed keys           |            — |            — |           — |                 — |              🆕 Candidate |
| Revocation enforcement         |            — |            — |           — |                 — |              🆕 Candidate |
| Replay resistance              |            — |            — |           — |                 — |              🆕 Candidate |
| Forgery resistance             |            — |            — |           — |                 — |              🆕 Candidate |
| Cross-service reuse prevention |            — |            — |           — |                 — |              🆕 Candidate |
| Timing-only attack             |            — |            — |           — |                 — |              🆕 Candidate |
| Timing release shaping         |            — |    UX timing |           ✅ |                 — |         🆕 Security angle |
| Runtime Claim Cap enforcement  |      Concept |            — |           — |            Design |              🆕 Candidate |
| Baseline poisoning             |            — |            — |           — |                 — |              🆕 Candidate |
| Event flooding/suppression     |            — |            — |           — |                 — |              🆕 Candidate |
| End-to-end BLE security        |            — |            — |           — |         Prototype |              🆕 Candidate |
| Token-verifying actuator       |            — |            — |           — |                 — |              🆕 Candidate |
| Fail-closed runtime            |            — |            — |           — |                 — |              🆕 Candidate |
| Recovery under attack          |            — |            — |           — |                 — |              🆕 Candidate |
| Attack Observatory             |            — |            — |           — |                 — |              🆕 Candidate |

---

# 10. Evidence Reuse Policy

## May Reuse With Citation

既存論文から以下を再掲する場合は、
必ず既存研究として明示する。

* motivation
* terminology
* dataset description
* existing baselines
* existing numerical results
* architecture concepts
* Claim Cap concept
* prior threat observations

---

## Must Be Re-run for Noticer Core

次の結果は、
Noticer Coreの実際のrelease surface上で再評価する。

* identity inference
* attribute inference
* semantic inference
* reconstruction
* linkability

理由:

Noticer Coreでは攻撃対象が
既存のrepresentation / ReleasePacketから
新しいcapability / timing / protocol traceへ変化するため。

---

## Must Be Entirely New Evidence

* replay attack
* forgery attack
* cross-service reuse
* cross-epoch reuse
* revocation
* key rotation
* timing-only linkage
* colluding-service attack
* Claim Cap runtime bypass
* baseline poisoning
* flooding / suppression
* BLE adversarial path
* physical actuator authorization
* fail-closed tests
* recovery tests
* runtime overhead

---

# 11. Forbidden Novelty Sentences

Noticer Core論文で、
以下の文を新規貢献として書いてはいけない。

### ❌

> We introduce within-person atypicality for privacy-preserving
> biosignal feedback.

Already claimed.

### ❌

> We introduce Claim Cap to prevent diagnostic feedback.

Already claimed.

### ❌

> We propose releasing low-cardinality claim tokens
> instead of biosignal latents.

Already claimed by CAPE-PPG-CED.

### ❌

> We keep raw PPG and continuous latents local.

Already claimed by CAPE-PPG-CED.

### ❌

> We evaluate identity, reconstruction, and membership leakage.

Already evaluated.

### ❌

> We propose a revocable Atypicality Token.

Too close to existing project conception unless
revocation semantics and enforcement are materially new and evaluated.

---

# 12. Candidate Novelty Sentences

実装と評価に成功した場合のみ使用できる。

### ✅ Candidate 1

> We present Noticer Core, a least-privilege reference monitor
> that mediates all biosignal declassification and converts
> locally derived atypicality into action-scoped capabilities.

### ✅ Candidate 2

> Unlike prior claim-bounded encoding, Noticer Core treats a
> biosignal release not as data to be interpreted but as a
> revocable authority to perform a specific action.

### ✅ Candidate 3

> We provide service- and epoch-scoped capability isolation,
> cryptographic freshness, replay resistance, and runtime
> revocation across the biosignal-to-actuator path.

### ✅ Candidate 4

> We show that value confidentiality alone is insufficient:
> timing traces enable cross-service inference even when
> released claim values are strongly bounded.

### ✅ Candidate 5

> We enforce Claim Cap as an executable runtime policy and
> demonstrate that unauthorized physiological claims and
> physical actions are rejected rather than merely discouraged.

### ✅ Candidate 6

> We evaluate Noticer Core against inference, timing,
> collusion, replay, forgery, poisoning, and flooding attacks
> in an end-to-end wearable-to-physical-actuator system.

---

# 13. Paper-Level Contribution Target

Noticer Coreの最終論文では、
貢献を以下の4本程度へ集約する。

## C1 — Security Abstraction

**Action-scoped biosignal capability**

生体状態を表すdata objectではなく、
限定されたaction authorityとしてdeclassifyする。

## C2 — Enforcing System

**Least-privilege biosignal reference monitor**

service isolation、epoch isolation、revocation、
freshness、Claim Capをruntimeで強制する。

## C3 — Adversarial Evaluation

**Value + timing + active attacks**

従来のrepresentation leakageだけでなく、
timing、collusion、replay、forgery、poisoning等を評価する。

## C4 — End-to-End Demonstration

**Wearable → Core → BLE → Menfugu**

情報量を制限したまま、
正当なutilityと物理的actionを維持できることを示す。

---

# 14. Red-Line Rule

次の条件を満たさない場合、
Noticer Coreを独立したトップセキュリティ論文として投稿しない。

* [ ] CAPE-PPG-CEDとの差を一文で説明できる
* [ ] capability semanticsを実装している
* [ ] cryptographic authority enforcementがある
* [ ] replay / forgery / cross-service attackを実施している
* [ ] timing leakageを評価している
* [ ] runtime Claim Capを実装している
* [ ] active attackerを最低1種類以上評価している
* [ ] end-to-end physical pathを実装している
* [ ] 過去論文だけでは成立しない新しい主要図表がある
* [ ] 主要contributionの過半数が新規evidenceに依存している

---

# 15. Current Working Boundary

現時点の研究境界を次のように固定する。

```text
Claim-Capped Biosignal Feedback
    ↓
What may the system claim?

CAPE-PPG-CED
    ↓
What information may cross the boundary?

Minute-CAPE
    ↓
When should feedback be released?

Noticer Core
    ↓
Who may exercise which release/action authority,
under what policy and lifetime,
and can that authority survive adversarial use?

Menfugu
    ↓
Can the bounded authority still create
a meaningful physical interaction?
```

---

# 16. Falsification

以下が判明した場合、
Noticer Coreの独立論文化を再検討する。

* capabilityが実質的にCAPE-PPG-CEDのReleasePacketと同一である
* cryptographyを追加しただけで研究上の新しいsecurity questionがない
* timing attackが実質的な問題にならない
* active attackが脅威モデル上不自然である
* runtime enforcementを行わず、policyを文章で定義するだけになる
* Menfugu統合が単なるdemo plumbingで終わる
* 主要評価結果が既投稿実験の再実行だけになる

その場合は、
新規論文を無理に作らず、
既存研究のartifact / system extensionとして位置づけ直す。
