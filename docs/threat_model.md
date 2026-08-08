# Noticer Core Threat Model v0.1

> **観測できることと、解釈・識別・再利用できることを分離する。**

Status: Draft  
Last Updated: 2026-08-09

---

## 1. Purpose

この文書は、Noticer Coreが想定するシステム境界、保護対象、
攻撃者、セキュリティ目標、非目標、必要な評価実験を定義する。

Noticer Coreは「ローカルで処理するから安全」とは主張しない。

安全性は、次の3点によって評価する。

1. 信頼境界外へ何を出さないか
2. 信頼境界外へ何だけを出すか
3. 出力を観測した攻撃者が何を推定・改ざん・再利用できるか

---

## 2. System Overview

Noticer Coreは、ウェアラブル生体信号を端末内で処理し、
外部サービスやアクチュエータには、制限された
Atypicality Capabilityだけを解放する。

```mermaid
flowchart LR
    SENSOR["Wearable Sensor<br>PPG / IBI / ACC"]

    subgraph CORE["Noticer Core / TCB"]
        Q["Signal Quality Gate"]
        E["Feature Encoder"]
        BASELINE["Personal Baseline"]
        A["Atypicality Engine"]
        P["Privacy / Release Shaper"]
        KEYSTORE["Hardware-backed Keystore"]
        T["Token Broker"]
        CLAIM["Claim Cap Monitor"]
        RENDERER["Trusted Renderer"]
    end

    APP["Untrusted Application / Service"]
    NET["BLE / Network Observer"]
    FUGU["Token-verifying Menfugu"]
    COLL["Colluding Services"]
    ATTACK["Adaptive ML Attacker"]

    SENSOR --> Q
    Q --> E
    E --> A
    BASELINE --> A
    A --> P
    KEYSTORE --> T
    P --> T
    T --> CLAIM
    CLAIM --> RENDERER
    CLAIM --> FUGU

    APP -. "queries / observes output" .-> CLAIM
    NET -. "observes traffic and timing" .-> T
    COLL -. "combines outputs" .-> T
    ATTACK -. "trains inference models" .-> T
````

---

## 3. System Entities

| ID | Entity | Role |
|---|---|---|
| `SENSOR` | Wearable Sensor | PPG、IBI、ACCなどを取得する |
| `CORE` | Noticer Core / TCB | 信号処理、baseline比較、release制御を行う |
| `BASELINE` | Personal Baseline | 本人の通常時分布を端末内に保持する |
| `KEYSTORE` | Keystore | サービス別・epoch別の鍵を保護する |
| `CLAIM` | Claim Cap Monitor | 許可された表示・通知・動作だけを通過させる |
| `RENDERER` | Trusted Renderer | Claim Capに従った表示だけを行う |
| `FUGU` | Menfugu | 正規tokenを検証し、許可された動作だけを実行する |
| `APP` | Application / Service | Noticer Coreの出力を利用する外部主体 |
| `NET` | Network Observer | BLEやネットワーク通信を観測する主体 |
| `ATTACK` | Adaptive Attacker | 出力から禁止情報を推定する攻撃者 |

---

## 4. Protected Assets

Noticer Coreが保護する対象を次に定義する。

### 4.1 Raw Physiological Data

* raw PPG
* IBI series
* raw ACC
* 高精度timestamp
* signal qualityの詳細な時系列

### 4.2 Derived Physiological Information

* continuous embeddings
* HRVなどの連続特徴量
* exact atypicality score
* confidence value
* 本人のbaseline分布
* baseline更新履歴

### 4.3 Identity and Attributes

* stable identity
* biometric identity
* age
* sex / gender attributes
* physiological morphology
* device-specific signature
* health-related attributes

### 4.4 Semantic Information

* stress
* valence
* arousal
* anxiety
* fatigue
* depression
* concentration
* diagnosis
* work-performance evaluation

### 4.5 Relational Information

* cross-session linkability
* cross-service linkability
* cross-device linkability
* cross-epoch linkability
* 行動時刻や生活リズムの推定

### 4.6 System Security Assets

* token authenticity
* token freshness
* token revocability
* policy integrity
* service separation
* Claim Cap enforcement
* baseline integrity

---

## 5. Trusted Computing Base

第一版では、以下を信頼する。

* 正規のウェアラブルセンサー
* センサーファームウェア
* ペアリング済み通信経路
* モバイルOSのプロセス分離
* モバイルOSのKeystore
* Noticer Coreプロセス
* 端末内baseline storage
* trusted renderer
* めんふぐ内のtoken verifier

### 5.1 TCB内に保持する情報

* raw PPG / IBI / ACC
* continuous embeddings
* personal baseline
* exact atypicality score
* confidence
* model parameters
* service keys
* epoch keys
* detailed timestamps

### 5.2 TCB外へ解放可能な情報

原則として次だけを解放する。

* `UNKNOWN`
* `USUAL`
* `SLIGHTLY_DIFFERENT`
* 本人が許可した特定動作を実行するopaque capability
* token検証に必要な最小限のmetadata

---

## 6. Attacker Knowledge

攻撃者は、次を知っているものとする。

* Noticer Coreの設計
* 使用しているアルゴリズム
* model architecture
* feature extraction method
* token formatの公開部分
* Claim Cap policy
* atypicalityの計算方法
* 評価用データセット
* 防御方式の存在

アルゴリズムを秘密にすることを、安全性の根拠にしない。

---

## 7. Attacker Capabilities

攻撃者は、次の能力を持ち得る。

* 多数の正規出力を収集する
* 長期間にわたって出力を観測する
* timing、頻度、欠損を観測する
* protected outputを用いて攻撃モデルを再学習する
* 補助的な公開情報を利用する
* 複数サービス間で出力を共有する
* 過去のtokenを保存・再送する
* tokenを書き換える
* 不正な入力によってbaseline更新を誘導する
* 大量のeventを発生させる
* 禁止された文言や動作を要求する

---

## 8. Adversary Catalog

### A1. Curious Application

正規のAPI利用権限を持つが、
必要以上の生体情報を取得しようとするアプリケーション。

**Goal**

* exact scoreを推定する
* stressなどの意味ラベルを推定する
* ユーザーの生活パターンを推定する

**Observed Surface**

* ReleasePacket
* action結果
* release timing
* missing events

---

### A2. Malicious Application

APIを意図的に乱用し、出力を大量収集または組み合わせる。

**Goal**

* identity inference
* attribute inference
* unauthorized profiling
* Claim Capの迂回

**Capabilities**

* repeated queries
* adaptive query selection
* local storage
* external auxiliary data

---

### A3. Colluding Services

複数サービスが、別々に受け取った出力を共有する。

**Goal**

* 同一ユーザーか判定する
* 異なる期間の記録を接続する
* 行動時刻を照合する
* サービス別tokenのdomain separationを破る

---

### A4. Passive Network Observer

BLEまたはネットワーク通信の内容、長さ、頻度、時刻を観測する。

**Goal**

* event発生時刻を推定する
* 利用者の行動パターンを推定する
* 通信だけから状態変化を分類する

暗号化されたpayloadだけでなく、
traffic analysisも評価対象にする。

---

### A5. Adaptive Inference Attacker

Noticer Coreの出力を入力として、
新しい攻撃モデルを訓練する。

**Goal**

* identity inference
* attribute inference
* semantic-label inference
* cross-session verification
* cross-service linkability

学習時に用いた弱いadversaryだけで安全性を評価しない。

---

### A6. Reconstruction Attacker

トークン、event sequence、timingから、
元の生体信号または特徴量を復元しようとする。

**Goal**

* raw PPG reconstruction
* IBI reconstruction
* HRV recovery
* morphology recovery
* 復元結果による下流分類

---

### A7. Replay and Forgery Attacker

過去のtokenを保存し、再送または改ざんする。

**Goal**

* めんふぐを不正に動作させる
* 失効済みtokenを再利用する
* action levelを書き換える
* 別サービスのtokenを転用する

---

### A8. Baseline-Poisoning Attacker

baseline更新期間に不正または偏った信号を混入させる。

**Goal**

* 通常状態の定義を意図的に移動させる
* eventを抑制する
* eventを過剰発生させる
* 特定の状況を通常として登録させる

---

### A9. Claim-Injection Attacker

許可されていない文言や動作を要求する。

**Examples**

* 「ストレス状態です」
* 「うつ傾向です」
* 「仕事の能力が低下しています」
* 管理者へ通知する
* ユーザーをランキングする
* 許可以上の強さでアクチュエータを動かす

---

### A10. Availability Attacker

システムを利用不能または過剰通知状態にする。

**Goal**

* event flooding
* event suppression
* BLE切断
* token exhaustion
* repeated invalid-token submission
* battery exhaustion

---

### A11. Bystander Observer

めんふぐやUIの変化を目視し、
本人の状態を推測する第三者。

**Goal**

* 膨張eventとstressなどを結びつける
* event頻度から本人の状態を推測する
* 複数日の変化を観察する

これはセキュリティコアだけでは完全には防げない。
Private Mode、Shared Mode、出力の曖昧性を含めて別途評価する。

---

## 9. Primary Security Goals

### G1. Data Confinement

raw PPG、IBI、continuous embedding、personal baselineを
TCB外へ送信しない。

### G2. Bounded Declassification

TCB外へ解放する情報を、
粗いatypicality eventまたは限定されたaction capabilityに制限する。

### G3. Empirical Inference Resistance

定義したadaptive attackerに対して、
identity、attribute、semantic label、reconstructionの成功度を測定し、
事前に定めた許容範囲以下に抑える。

### G4. Domain Separation

異なるservice、device、epochのtokenを、
直接転用または容易に照合できないようにする。

### G5. Integrity and Freshness

改ざん、偽造、期限切れ、replayされたtokenを拒否する。

### G6. Claim Enforcement

許可されていない文言、数値、通知先、actionを拒否する。

### G7. Fail-Closed Behavior

次の場合は、積極的な推定や通知を行わない。

* signal qualityが低い
* baselineが不足している
* model versionが不一致
* token verificationに失敗する
* policyが読み込めない
* confidenceが不足している

これらの場合は `UNKNOWN` または無動作にする。

### G8. Local Revocability

本人がservice authorizationを取り消した場合、
以後のtoken生成を停止し、旧tokenを期限後に利用不能にする。

---

## 10. Non-Goals

第一版では、次を保証しない。

* 完全匿名性
* 情報理論的に完全なunlinkability
* あらゆる補助情報を持つ攻撃者への耐性
* root化されたOSからの保護
* 悪意あるセンサーファームウェアへの耐性
* 電力・電磁波などの物理side-channel耐性
* 端末を物理的に完全取得された場合の保護
* 本人が意図的に公開した情報の保護
* 人間による自由な意味解釈の完全な防止
* 医療診断としての正確性
* stress、depression、fatigueなどの真値推定
* 不正確なセンサーそのものの完全補正

---

## 11. Release Surface

外部へ解放するpacketは、最小限の概念として次を持つ。

```text
ReleasePacket
├── protocol_version
├── service_domain
├── epoch_identifier
├── bounded_action
├── coarse_time_bucket
├── expiration
├── sequence_number
├── policy_hash
├── nonce
└── authentication_tag
```

### ReleasePacketに含めないもの

* raw signal
* embedding
* exact atypicality score
* confidence
* exact timestamp
* baseline statistics
* identity
* demographic attributes
* diagnostic label
* human-readable physiological interpretation

この構造は暫定であり、
各fieldが生むlinkabilityを攻撃評価によって検証する。

---

## 12. Attack-to-Evidence Matrix

| Attack                  | Protected Property     | Evaluation                               | Success Criterion         |
| ----------------------- | ---------------------- | ---------------------------------------- | ------------------------- |
| Identity classification | Identity privacy       | Closed/open-set identification           | `[TBD before experiment]` |
| Identity verification   | Unlinkability          | ROC-AUC / EER                            | `[TBD before experiment]` |
| Attribute inference     | Attribute privacy      | Macro-F1 / ROC-AUC                       | `[TBD before experiment]` |
| Semantic inference      | Semantic privacy       | ROC-AUC / AUPRC                          | `[TBD before experiment]` |
| Waveform reconstruction | Raw-data privacy       | Correlation / DTW / downstream recovery  | `[TBD before experiment]` |
| Cross-session linkage   | Temporal unlinkability | Pairwise AUC / EER                       | `[TBD before experiment]` |
| Cross-service linkage   | Domain separation      | Pairwise AUC / attack advantage          | `[TBD before experiment]` |
| Timing-only inference   | Traffic privacy        | AUC using timestamps only                | `[TBD before experiment]` |
| Replay                  | Freshness              | Unauthorized acceptance rate             | `0 in test suite`         |
| Token forgery           | Integrity              | Unauthorized acceptance rate             | `0 in test suite`         |
| Cross-service reuse     | Domain separation      | Unauthorized acceptance rate             | `0 in test suite`         |
| Baseline poisoning      | Baseline integrity     | Drift / false-event rate / recovery time | `[TBD before experiment]` |
| Claim injection         | Claim enforcement      | Policy bypass rate                       | `0 in policy test suite`  |
| Event flooding          | Availability           | Maximum sustainable rate / recovery      | `[TBD before experiment]` |

---

## 13. Dataset Splitting Requirements

プライバシー評価では、隣接windowの漏えいを避ける。

最低限、次を区別して評価する。

* session-disjoint
* day-disjoint
* subject-disjoint where applicable
* device-disjoint where applicable
* temporal-block-disjoint

禁止する評価方法:

* 連続時系列をランダムなwindowへ分割するだけ
* 同一sessionの隣接windowをtrain/testへ混在させる
* 防御学習に使った攻撃器だけでprivacyを判定する
* 最も都合のよいモデルとparameterだけを報告する
* timing情報を無視してunlinkabilityを主張する

---

## 14. Open Security Decisions

以下は、実装前または評価前に固定する。

* [ ] release alphabetを何段階にするか
* [ ] `UNKNOWN`を外部へ通知するか、無動作にするか
* [ ] epochの期間
* [ ] token expirationの長さ
* [ ] exact timestampをどの粒度へ丸めるか
* [ ] release timingへjitterを入れるか
* [ ] cooldown duration
* [ ] service key derivation method
* [ ] baseline更新を許可する条件
* [ ] poisoning検知方法
* [ ] acceptable identity leakage threshold
* [ ] acceptable linkability threshold
* [ ] acceptable utility degradation
* [ ] Private / Shared Modeの境界
* [ ] Android Keystoreまたは別実装の選択
* [ ] TEEを将来のTCBへ含めるか

---

## 15. Falsification Principle

Noticer Coreの評価目的は、
安全であることを演出することではない。

次のいずれかが成立した場合、
現在のsecurity claimを縮小または撤回する。

* protected outputからidentityが安定して推定できる
* timingだけでservice間照合が成立する
* raw signalの有意味な復元が可能である
* semantic labelが高精度に推定できる
* replayまたはforgeryが受理される
* Claim Capを迂回できる
* baseline poisoningが現実的な回数で成功する
* utilityを維持するために高密度情報の解放が必要になる

失敗結果は隠さず、設計変更または主張範囲の縮小に使う。

````

作成後はこれだけcommitします。

```bash
git add docs/threat_model.md
git commit -m "docs: define the Noticer Core threat model"

