# K4 脅威モデル

## 保護対象

- private biosignal history
- private evidenceとbaseline差分
- action semanticsを超えるcondition、identity、時刻情報
- issuer、transport、verifierの鍵
- replay stateと失効stateの完全性
- pumpが許可なしに動かないという物理安全性

## 攻撃者

| 攻撃者 | 能力 | K4の応答 |
|---|---|---|
| Network Observer | 全BLE writeと時刻を観測 | 固定20x20、固定cadence、公開loss tape評価 |
| Active Link Attacker | drop、duplicate、reorder、mutation | bounded reassembly、FEC、ATv2認証、fail closed |
| Replay Attacker | 完全frameを再送 | atomic replay guardとactuator consumption |
| Malicious App | retryや接続差を作る | sender APIにretryを持たせず20 slotを固定 |
| Stale Receiver | 古いkey/policyを保持 | epoch binding、revocation snapshot、freshness |
| Physical Attacker | pump outputを直接操作 | 本K4の範囲外。hardware safety caseが必要 |

## Attack-to-evidence matrix

| Attack | Test/evidence | Pass condition |
|---|---|---|
| malformed fragment | transport-core parser test | panicなし、拒否 |
| conflicting duplicate | reassembler test | frame破棄 |
| reorder | fragment indexによる再構成 | 正規envelopeのみ完成 |
| interleaved loss | indices 0,5,10,15 drop | 4 parityで回復 |
| excess loss | timeout/capacity contract | verifier未呼出 |
| parity corruption | parity consistency test | 拒否またはATv2認証拒否 |
| token mutation | K3 verifier test | Rejected |
| expiry/revocation | K3 verifier test | Rejected |
| replay | K4 demo second delivery | pump transition増加なし |
| unsupported action | menfugu-core test | pumpなし |
| pair distinguisher | K4 observer trace equality | 全20 wire observation一致 |

## Non-goals

- RF fingerprintingやdevice hardware identifierの秘匿
- OS/BLE controller固有jitterの証明
- denial of service防止
- Byzantine FEC
- pump機構そのものの機械安全認証
- Tier Aだけから実機性能を主張すること
