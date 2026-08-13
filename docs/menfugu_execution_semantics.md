# めんふぐ実行セマンティクス

## 許可action

物理実行器が受理するactionはMenfuguInflateSoftだけである。NoAction、renderer向けaction、
未知actionはすべて拒否する。実行器への入力はnoticer-verifier-coreが生成したsealed
AuthorizedActionに限定する。

## 状態機械

状態はIdle、Pumping、Cooldownの三つである。

| Current | Input | Guard | Next | Output |
|---|---|---|---|---|
| Idle | AuthorizedAction | soft inflate、公開slot、未消費 | Pumping | PumpOn |
| Idle | その他 | 任意 | Idle | なし |
| Pumping | timer before stop | 任意 | Pumping | なし |
| Pumping | timer at/after stop | 任意 | Cooldown | PumpOff |
| Cooldown | slot before bound | 任意 | Cooldown | なし |
| Cooldown | slot at/after bound | 任意 | Idle | なし |

pump durationは設定値をmaximum pump duration以下に検証し、tokenから可変値を受け取らない。
cooldownとexecution period/offsetも公開設定である。tick加算またはslot加算がoverflowする場合は
動作しない。

## 消費規則

verifier replay guardがtokenをone-shotにし、actuatorも固定容量のtoken ID windowで二重実行を
防ぐ。容量は無制限に増えない。容量ゼロ設定はfail closedである。製品実装ではpersistent
replay storeを用い、actuator windowは電源断直後の追加防御として扱う。

## Error surface

GATT peerへ詳細な検証errorを返さない。firmware runtimeはRejectedへ正規化し、pump outputを
lowに維持する。local debug buildでもkey、nonce、token ID、private evidenceをlogへ出さない。

## Safety boundary

本実装は論理pump outputまでを検証する。圧力sensor、mechanical relief valve、battery、
thermal limit、material fatigueは別のhardware safety caseを必要とし、Tier A成功から安全性を
推論してはならない。
