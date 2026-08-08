# Noticer Core Decision Log

この文書には、
研究途中で「なぜそうしたのか」を忘れないための
主要設計判断を記録する。

---

## D001 — Presenteeism is a Use Case, Not the Security Claim

**Status:** Accepted

プレゼンティーズムは重要な応用領域だが、
Noticer Coreのsecurity contributionそのものではない。

Primary framing:

> least-privilege declassification of wearable biosignals

Presenteeismはmotivation / deployment exampleとして扱う。

---

## D002 — Observation and Interpretation Are Separated

**Status:** Accepted

生体観測値から内部状態ラベルへの変換を、
当然の処理として扱わない。

> Observation is a fact. Interpretation is a claim.

を設計原則とする。

---

## D003 — Claim Cap and Leakage Cap Are Different

**Status:** Accepted

### Leakage Cap

外部出力から何を推定できるか。

### Claim Cap

システムが何を表示・通知・実行できるか。

両者は独立して評価する。

---

## D004 — Privacy Is Not Claimed From Local Processing Alone

**Status:** Accepted

「ローカル処理だから安全」という主張は禁止する。

出力、timing、metadata、token sequence、
physical actuationからの漏えいを評価する。

---

## D005 — Do Not Claim Perfect Anonymity

**Status:** Accepted

評価前に以下を主張しない。

- anonymous
- irreversible
- identity-free
- unlinkable
- perfectly private

明示した攻撃モデル下で測定された結果のみ主張する。

---

## D006 — CAPE Is Internal; Noticer Core Is the Enforcement Boundary

**Status:** Accepted

CAPE / PCAEは内部privacy mechanism候補。

Noticer Coreの新規性はencoder単体性能ではなく、

> authority and declassification enforcement

に置く。

---

## D007 — Release an Authority, Not a Physiological Description

**Status:** Accepted

公開objectを、

```text
"This user is atypical"
```

というdata tokenから、

```text
"This verifier may perform ACTION_X once"
```

というcapabilityへ移す。

---

## D008 — Capability Must Be Scoped

**Status:** Accepted

最低限、

* service
* action
* epoch
* lifetime
* sequence / nonce
* policy

で権限を制限する。

---

## D009 — Timing Is Part of the Attack Surface

**Status:** Accepted

payload暗号化だけでは十分ではない。

以下を攻撃対象とする。

* event timing
* frequency
* silence
* burst
* packet size
* cross-service temporal correlation

---

## D010 — Menfugu Is a Reference Actuator

**Status:** Accepted

Menfugu自体をNoticer Coreのalgorithmic noveltyとはしない。

役割：

> bounded authorityだけでも、
> meaningful physical utilityが成立することを示す。

---

## D011 — Menfugu Must Not Understand Physiology

**Status:** Accepted

Menfugu firmwareは、

* stress
* HRV
* PPG
* atypicality score

を扱わない。

知るのは、

* capability validity
* authorized action

のみ。

---

## D012 — Fail Closed

**Status:** Accepted

不明・異常・検証失敗時は、
推定を強くしたりactionを実行したりしない。

```text
UNKNOWN / INVALID
→ no privileged action
```

---

## D013 — Adaptive Attackers Are Required

**Status:** Accepted

防御学習に使用したattack modelだけを評価しない。

攻撃者は公開方式を知り、
protected outputを用いて再学習可能とする。

---

## D014 — Active Attacks Are Part of Noticer Core

**Status:** Accepted

Noticer Coreではpassive inferenceに加え、

* replay
* forgery
* poisoning
* flooding
* suppression
* service collusion

を扱う。

---

## D015 — Prior Research Is Prior Research

**Status:** Accepted

既存論文で主張済みの、

* within-person atypicality
* Claim Cap concept
* privacy encoder
* low-cardinality release
* ReleasePacket
* representation leakage evaluation

をNoticer Coreの新規性として再主張しない。

---

## D016 — Implementation Before Expansion

**Status:** Accepted

新しい機能は、

* security claim
* attack resistance
* utility
* reproducibility
* end-to-end demo

のいずれにも寄与しない場合は追加しない。

---

## D017 — Attack Observatory Is Part of the Research Artifact

**Status:** Accepted

Attack Observatoryは単なる展示UIではなく、

* raw baseline attack
* capability attack
* replay
* forgery
* timing attack
* Claim Cap denial

を再現可能にする研究artifactとして設計する。

---

## D018 — Publication Claim Must Survive Falsification

**Status:** Accepted

攻撃が成功した場合は、

* 防御を修正する
* claimを縮小する
* limitationとして明示する

のいずれかを行う。

結果を隠してstrong claimを維持しない。
