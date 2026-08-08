# Noticer Core Research Constitution v0.1

## 1. Primary Research Question

Can an on-device reference monitor declassify only
short-lived and service-separated within-person atypicality
capabilities from wearable PPG, while bounding identity,
attribute, semantic, reconstruction, and cross-service
linkability leakage under adaptive attackers?

日本語：
ウェアラブルPPGから、短命かつサービス間で分離された
「本人内の非典型性に反応する能力」だけを外部へ解放し、
適応的な攻撃者に対して、本人性・属性・意味ラベル・波形復元・
サービス間照合の漏えいを抑制できるか。

## 2. Allowed Information

Noticer Coreの信頼境界外へ解放してよい情報は、次に限定する。

- 本人内で校正された粗い非典型性イベント
- 信号品質不足を表す UNKNOWN
- 本人が事前に許可した、範囲の限定されたアクチュエータ動作
- トークンの有効期限、失効、検証に必要な最小限のメタデータ

## 3. Forbidden Information

信頼境界外へ出してはならない情報は、次とする。

- 生PPGおよびIBI
- 連続的な生体特徴量またはembedding
- 本人のローカルbaseline
- 安定した本人識別情報
- 年齢、性別、身体的特徴、デバイス固有情報
- stress、valence、arousal、診断状態などの意味ラベル
- 元波形を復元できる情報
- 異なるサービス、鍵エポック、期間を照合できる情報
- 正確な非典型性スコアおよびconfidence
- 必要以上に正確なtimestamp

## 4. Trusted Computing Base

第一版では次を信頼する。

- PPGセンサーおよびその正規の通信経路
- Noticer Coreプロセス
- ハードウェアバックドKeystore
- 本人端末内のbaseline
- Claim Capを強制するtrusted renderer
- Atypicality Tokenを検証するめんふぐfirmware

次は第一版の保護対象外とする。

- OS全体が完全に侵害された場合
- センサーファームウェア自体が悪意を持つ場合
- 物理的に端末を完全取得された場合
- 人間が外見的変化から自由に意味を推測すること
- 本人が生データ公開を明示的に許可した場合

## 5. Adversaries

最低限、次の攻撃者を評価する。

1. Curious application
2. Malicious application
3. Colluding services
4. BLE or network observer
5. Adaptive machine-learning attacker
6. Identity and attribute inference attacker
7. Waveform reconstruction attacker
8. Cross-service and cross-epoch linkability attacker
9. Timing-only attacker
10. Replay and token-forgery attacker
11. Baseline-poisoning attacker
12. Event-flooding and event-suppression attacker

## 6. Output Contract

TCB外へ渡す出力は、原則として次のいずれかとする。

- UNKNOWN
- USUAL
- SLIGHTLY_DIFFERENT
- 本人が許可した特定動作だけを実行できるopaque action capability

連続値のatypicality scoreやcontinuous embeddingは渡さない。

## 7. Primary Security Claim

Noticer Coreは、生PPG、baseline、連続embeddingを
信頼境界内に保持し、外部アプリまたはアクチュエータには、
本人が許可した低帯域な非典型性capabilityだけを解放する。

この機構は、定義した適応的攻撃者に対して、
許可されたchange utilityを維持しながら、
identity、attribute、semantic inference、
reconstruction、linkabilityを定量的に制限する。

## 8. Claim Cap

Claim CapとLeakage Capを分離する。

- Leakage Cap:
  トークンや出力から何を推定できるかを制限する。

- Claim Cap:
  システムがユーザーに対して何を表示・発話・実行してよいかを制限する。

許可する表現例：

- 「少し見直す？」
- 抽象的な触覚通知
- めんふぐの段階的な膨張
- UNKNOWN時の無表示

禁止する表現例：

- 「ストレス状態です」
- 「集中力が低下しています」
- 「うつ傾向です」
- 「休むべきです」
- 管理者への状態通知
- 人事評価、ランキング、診断スコア

## 9. Explicit Non-Claims

評価が完了するまで、次を主張しない。

- 完全な匿名性
- 数学的に完全な非可逆性
- 本人性の完全除去
- あらゆる攻撃者に対するunlinkability
- stressや疾患の正確な検出
- 医療診断への利用可能性
- ローカル処理だけで安全性が保証されること
- 鍵更新だけで統計的照合が防止されること

## 10. Required Evidence

主張には、最低限次の証拠を対応させる。

- Change utility evaluation
- Identity inference attack
- Attribute inference attack
- Semantic-label inference attack
- Waveform reconstruction attack
- Cross-session linkability attack
- Cross-service linkability attack
- Timing-only attack
- Replay and token-forgery tests
- Baseline-poisoning evaluation
- Privacy–utility frontier
- Latency, memory, energy, and bandwidth measurements
- Reproducible experiment scripts

## 11. Reference Application

めんふぐは研究の中心アルゴリズムそのものではなく、
Atypicality Tokenだけで有用な身体的体験が成立することを示す
reference actuatorと位置づける。

めんふぐへ生PPG、連続スコア、診断ラベルは送らない。

## 12. Primary Submission Strategy

Primary:
- Privacy-enhancing technology / usable security venue

Secondary:
- Security and privacy journal
- Human-computer interaction paper for the experiential evaluation
- Interactive demo venue for Attack Observatory + Menfugu

## 13. Project Rule

新規機能は、それが以下のどれを改善するか説明できる場合に限り追加する。

- Security claim
- Attack resistance
- Change utility
- Reproducibility
- End-to-end demonstration

説明できない機能は、少なくともトップ層論文の投稿までは追加しない。