<div align="center">

# 🌊🐡 Noticer Core

### **観測は事実だが解釈は主張である。**  
### **Observation is a fact. Interpretation is a claim.**

<br>

![status](https://img.shields.io/badge/status-research%20prototype-8A2BE2?style=for-the-badge)
![privacy](https://img.shields.io/badge/privacy-by%20design-1E90FF?style=for-the-badge)
![security](https://img.shields.io/badge/security-least--privilege-DC143C?style=for-the-badge)
![biosignals](https://img.shields.io/badge/biosignals-PPG%20%2F%20IBI%20%2F%20HRV-20B2AA?style=for-the-badge)
![claim-capped](https://img.shields.io/badge/output-claim--capped-FF8C00?style=for-the-badge)
![language](https://img.shields.io/badge/lang-JP%20%7C%20EN-2E8B57?style=for-the-badge)

<br>

**A least-privilege security runtime for claim-capped declassification of wearable biosignals.**

**ウェアラブル生体信号から、本人内の変化だけを最小権限で解放するためのセキュリティ基盤。**

</div>

---

## 目次 / Table of Contents

- [🇯🇵 日本語](#-日本語)
  - [これは何か](#これは何か)
  - [なぜ作るのか](#なぜ作るのか)
  - [コアアイデア](#コアアイデア)
  - [研究の問い](#研究の問い)
  - [システムの輪郭](#システムの輪郭)
  - [このリポジトリで扱うもの](#このリポジトリで扱うもの)
  - [進捗](#進捗)
  - [思想](#思想)
  - [将来のデモ](#将来のデモ)
  - [リポジトリ構成](#リポジトリ構成)
- [🇬🇧 English](#-english)
  - [What this is](#what-this-is)
  - [Why this exists](#why-this-exists)
  - [Core idea](#core-idea)
  - [Research question](#research-question)
  - [System sketch](#system-sketch)
  - [What this repository contains](#what-this-repository-contains)
  - [Progress](#progress-1)
  - [Philosophy](#philosophy)
  - [Future demo](#future-demo)
  - [Repository structure](#repository-structure)

---

# 🇯🇵 日本語

## これは何か

**Noticer Core** は、  
ウェアラブルから得られる **PPG / IBI / HRV などの高密度な生体信号** を、  
そのまま外部に渡すのではなく、

> **「本人内でいつもと少し違う」ことだけを、  
> 短命で・限定的で・低主張な形に変換して解放する**

ための、**セキュリティ研究用コア基盤**です。

これは単なる「生体データ活用」ではありません。  
むしろ逆です。

- 生データは出さない
- 連続スコアも出さない
- 「ストレスです」とも言わない
- 「診断」もしない
- それでも気づきと行動のきっかけは残す

そのための仕組みを、  
**セキュリティ / プライバシー / HCI / フィジカルインタラクション** の交点として作ります。

---

## なぜ作るのか

今の多くのセンシングシステムは、  
人の身体から得たデータを **「より正確に読む」** 方向へ進みます。

でも私は、別の問いを置きたい。

> **人は、そんなに断定されたいのか？**  
> **身体から得た微細な変化は、誰かに解釈される前に、  
> まず本人のものとして留まるべきではないか？**

Noticer Core は、  
「分かることを増やす」のではなく、

> **分かりすぎないまま、役に立てる**

ための技術です。

---

## コアアイデア

<div align="center">

| 生データ中心の設計 | Noticer Coreの設計 |
|---|---|
| raw PPG を渡す | raw PPG は渡さない |
| 連続値スコアを返す | 粗い変化イベントだけ返す |
| ストレス・感情を推定する | 意味ラベルを直接出さない |
| アプリ側が自由に解釈する | Claim Cap で出力を制限する |
| 高情報量ゆえに漏えいしやすい | 最小情報で utility を残す |

</div>

このプロジェクトの核は、次の4層です。

### 1. **Atypicality**
「その人にとって、いつもと少し違う」を扱う。  
他人との比較よりも、**本人内の変化**を重視する。

### 2. **Leakage Cap**
外に出た情報から、
- 本人性
- 属性
- 感情ラベル
- 元波形
- サービス間照合性

などを推定されにくくする。

### 3. **Claim Cap**
外部システムが勝手に
- 「ストレスです」
- 「集中力が低下しています」
- 「うつ傾向です」

などと断定しないよう、  
**表示・発話・アクションの語彙と権限を制約する。**

### 4. **Reference Actuation**
最小限の情報だけでも、  
**めんふぐ**のようなフィジカルな外化デバイスで  
「おお、成立してる」と体感できるようにする。

---

## 研究の問い

> **Can an on-device reference monitor declassify only short-lived, service-separated within-person atypicality capabilities from wearable biosignals, while bounding identity, attribute, semantic, reconstruction, and cross-service linkability leakage under adaptive attackers?**

日本語で言うと：

> **ウェアラブル生体信号から、短命かつサービス間で分離された  
> 「本人内の非典型性に反応する能力」だけを外部へ解放し、  
> 適応的な攻撃者に対して、本人性・属性・意味ラベル・波形復元・  
> サービス間照合の漏えいを抑えられるか？**

---

## システムの輪郭

```text
Wearable Sensor (PPG / IBI / ACC)
                │
                ▼
      ┌─────────────────────┐
      │    Noticer Core     │
      │─────────────────────│
      │ Signal Quality Gate │
      │ Personal Baseline   │
      │ Atypicality Engine  │
      │ Privacy Filter      │
      │ Token Broker        │
      │ Claim Cap Monitor   │
      └─────────────────────┘
                │
                ▼
  Opaque, short-lived, low-claim output
                │
      ┌─────────┴─────────┐
      ▼                   ▼
 Trusted UI          Menfugu / Actuator
````

---

## このリポジトリで扱うもの

### ✅ 扱う

* オンデバイス生体信号処理
* baseline / atypicality 推定
* privacy-preserving representation
* tokenization / revocation / replay resistance
* claim-capped output policy
* attack harness
* end-to-end demo pipeline
* reproducible experiments

### ❌ まだ中心にしない

* 医療診断
* メンタルヘルスの断定分類
* 管理者ダッシュボード
* ユーザーランキング
* 他者評価のためのセンシング
* 「高精度なストレス推定」そのもの

---

## 進捗

### Research Gates

* [ ] **W1** Research Constitution / Threat Model / Claim Matrix
* [ ] **W2** Raw & baseline attacks (identity / attribute / reconstruction / linkability)
* [ ] **W3** Atypicality engine / baseline / conformal calibration
* [ ] **W4** Privacy filter / PCAE / frontier analysis
* [ ] **W5** Token broker / key rotation / replay defense / Claim Cap
* [ ] **W6** Adaptive attacks / timing-only / collusion / poisoning
* [ ] **W7** Attack Observatory + Menfugu integrated demo
* [ ] **W8** Reproducible artifacts / figures / paper draft

---

## 思想

<details>
<summary><strong>クリックでひらく：この研究の温度</strong></summary>

<br>

私は、
「身体の微細な変化を、社会がもっと正確に読むべきだ」
とは、必ずしも思っていません。

むしろ逆に、

* 読みすぎない
* 決めつけすぎない
* 他者に管理されすぎない
* でも、自分では気づける
* 必要なら、そっと行動を変えられる

そういう技術があっていいと思っています。

これは弱い技術ではありません。
**断定しないことを、きちんと実装する** のは、かなり難しい。

Noticer Core は、

> **「観測はできる。でも、解釈の権限は暴走させない」**

という立場のもとで作られます。

私は、
「生きててよかった」が生まれる技術を作りたい。
そのためにまず、
**身体から取れる情報を、むやみに人の外へ差し出さない**
ところから始めます。

</details>

---

## 将来のデモ

<details>
<summary><strong>クリックでひらく：最終的に見せたい “おお！” デモ</strong></summary>

<br>

### Attack Observatory + Menfugu

1. ライブでPPGを取る
2. 従来方式では attacker が identity / reconstruction / label inference に成功する
3. Noticer Core に切り替える
4. めんふぐはちゃんと膨らむ
5. でも attacker 側の画面は崩れる
6. 古い token は replay できない
7. 悪意ある文言「ストレス状態です」は Claim Cap に拒否される

つまり、

> **役に立つのに、漏らしすぎない。**
> **動くのに、断定しすぎない。**

を、目の前で体験できるデモにしたい。

</details>

---

## リポジトリ構成

```text
noticer-core/
├── README.md
├── docs/
│   ├── research_constitution.md
│   ├── threat_model.md
│   ├── claim_matrix.md
│   ├── system_boundary.md
│   └── decision_log.md
├── core/                   # signal processing / baseline / atypicality
├── privacy/                # privacy filter / representation learning
├── token/                  # token broker / keys / revocation / replay defense
├── policy/                 # Claim Cap policy
├── attacks/                # attack implementations and evaluations
├── experiments/            # reproducible experiments
├── apps/
│   └── attack-observatory/
├── firmware/
│   └── menfugu/
├── tests/
└── artifacts/
```

---

## 開発のルール

* **主張より先に証拠**
* **精度より先に脅威モデル**
* **機能より先に境界**
* **成功例より先に壊し方**
* **研究は passion、評価は冷酷に**

---

## 一言でいうと

> **Noticer Core は、
> 生体信号を“読む技術”ではなく、
> 生体信号を“渡しすぎないまま役立てる技術”です。**

---

<br>
<br>

# 🇬🇧 English

## What this is

**Noticer Core** is a research-grade security runtime for wearable biosignals such as **PPG / IBI / HRV**.

Instead of exposing raw biosignals to external applications, it aims to:

> **release only a bounded, short-lived, low-claim notion of “something is slightly unusual for this person,”**
> while keeping raw data, rich features, and strong interpretations inside the trust boundary.

This is not a project about extracting more from the body.

It is about the opposite:

* do **not** export raw signals
* do **not** export continuous scores
* do **not** say “you are stressed”
* do **not** perform diagnosis
* and still preserve enough utility for awareness and action

This repository sits at the intersection of
**security, privacy, HCI, and physical interaction**.

---

## Why this exists

Many sensing systems move toward **reading the body more accurately**.

This project asks a different question:

> **Do people really want to be interpreted that aggressively?**
> **Should subtle bodily changes first remain with the person, before becoming somebody else’s claim?**

Noticer Core is a technical attempt to make systems that are useful while **not understanding too much**.

---

## Core idea

<div align="center">

| Typical sensing pipeline       | Noticer Core                          |
| ------------------------------ | ------------------------------------- |
| Export raw PPG                 | Do not export raw PPG                 |
| Return continuous scores       | Return only coarse atypicality events |
| Infer stress / affect labels   | Avoid direct semantic claims          |
| Let apps interpret freely      | Constrain outputs with Claim Cap      |
| High information, high leakage | Minimal information, retained utility |

</div>

The core architecture has four layers:

### 1. **Atypicality**

Model **within-person change**, not primarily between-person comparison.

### 2. **Leakage Cap**

Bound what external observers can infer, including:

* identity
* attributes
* semantic labels
* waveform characteristics
* cross-service linkability

### 3. **Claim Cap**

Constrain what the system is allowed to say or do, so that it does not freely output:

* “you are stressed”
* “your concentration is declining”
* “you may be depressed”

### 4. **Reference Actuation**

Show that even minimal output can still be meaningful through a physical actuator such as **Menfugu**.

---

## Research question

> **Can an on-device reference monitor declassify only short-lived, service-separated within-person atypicality capabilities from wearable biosignals, while bounding identity, attribute, semantic, reconstruction, and cross-service linkability leakage under adaptive attackers?**

---

## System sketch

```text
Wearable Sensor (PPG / IBI / ACC)
                │
                ▼
      ┌─────────────────────┐
      │    Noticer Core     │
      │─────────────────────│
      │ Signal Quality Gate │
      │ Personal Baseline   │
      │ Atypicality Engine  │
      │ Privacy Filter      │
      │ Token Broker        │
      │ Claim Cap Monitor   │
      └─────────────────────┘
                │
                ▼
  Opaque, short-lived, low-claim output
                │
      ┌─────────┴─────────┐
      ▼                   ▼
 Trusted UI          Menfugu / Actuator
```

---

## What this repository contains

### ✅ In scope

* on-device biosignal processing
* baseline / atypicality estimation
* privacy-preserving representations
* tokenization / revocation / replay resistance
* claim-capped output policies
* attack harnesses
* end-to-end demos
* reproducible experiments

### ❌ Not the current focus

* medical diagnosis
* strong mental-state classification
* manager dashboards
* user ranking
* sensing for third-party evaluation
* “stress prediction accuracy” as the main product

---

## Progress

### Research Gates

* [ ] **W1** Research Constitution / Threat Model / Claim Matrix
* [ ] **W2** Raw & baseline attacks (identity / attribute / reconstruction / linkability)
* [ ] **W3** Atypicality engine / baseline / conformal calibration
* [ ] **W4** Privacy filter / PCAE / frontier analysis
* [ ] **W5** Token broker / key rotation / replay defense / Claim Cap
* [ ] **W6** Adaptive attacks / timing-only / collusion / poisoning
* [ ] **W7** Attack Observatory + Menfugu integrated demo
* [ ] **W8** Reproducible artifacts / figures / paper draft

---

## Philosophy

<details>
<summary><strong>Click to expand: the temperature of this project</strong></summary>

<br>

This project is not built on the belief that society should always read the body more precisely.

It is built on the opposite hope:

* do not overread
* do not overclaim
* do not overmanage people
* and still make room for awareness
* and still allow gentle action

That is not a weak design choice.
It is actually hard.

Noticer Core is built from the position that:

> **observation may happen, but the power to interpret should not be allowed to run wild.**

I want to build technologies that can contribute to moments when someone feels:

> **“I’m glad I’m here.”**

And to do that, I want to begin by making sure that bodily information is **not handed away too easily**.

</details>

---

## Future demo

<details>
<summary><strong>Click to expand: the “wow” demo we want to build</strong></summary>

<br>

### Attack Observatory + Menfugu

1. Capture live PPG
2. Show that a conventional pipeline allows identity / reconstruction / label inference
3. Switch to Noticer Core
4. Menfugu still inflates properly
5. The attacker’s inferences collapse
6. Old tokens cannot be replayed
7. Malicious phrases such as “you are stressed” are blocked by Claim Cap

The goal is a demo that makes people feel:

> **useful, but not overexposed**
> **working, but not overclaiming**

</details>

---

## Repository structure

```text
noticer-core/
├── README.md
├── docs/
│   ├── research_constitution.md
│   ├── threat_model.md
│   ├── claim_matrix.md
│   ├── system_boundary.md
│   └── decision_log.md
├── core/
├── privacy/
├── token/
├── policy/
├── attacks/
├── experiments/
├── apps/
│   └── attack-observatory/
├── firmware/
│   └── menfugu/
├── tests/
└── artifacts/
```

---

## Development rules

* **Evidence before claims**
* **Threat model before accuracy**
* **Boundary before features**
* **Failure modes before success stories**
* **Passion in building, coldness in evaluation**

---

## In one sentence

> **Noticer Core is not a technology for reading biosignals.
> It is a technology for making biosignals useful without giving away too much.**

---

<div align="center">

### ✨ Built with passion, doubt, restraint, and a desire to make technology kinder without making it weaker.

</div>
