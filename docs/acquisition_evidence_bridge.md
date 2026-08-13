# Acquisition to Evidence Bridge

## 目的

`noticer-evidence-bridge`は、K5のprivate acquisition windowを既存K1 `EvidenceEngine`へ一方向に接続する。既存の`PrivateObservation`、`PrivateFeatureVector`、`EvidencePermit`を複製しない。

## Pre-K1 gates

bridgeはK1のstateを更新する前に次を全て検査する。

- windowのopaque `SessionId`がbridgeへ固定したMonitoring sessionと一致する
- window phaseが`Monitoring`である
- `FeatureSchema::id()`が固定したschema IDと一致する
- qualityが`Usable`以上である
- logical slotの加算がoverflowしない

いずれかが失敗した場合、K1 `EvidenceEngine::process`を呼ばず`UNKNOWN`を返す。特にK1はslotを先に記録してからqualityを評価するため、quality gateはbridge側で先行させる。

Reference、Calibration、Monitoringは別sessionであり、Reference/Calibration windowをMonitoring bridgeへ渡してもbaselineやevidence stateを更新しない。

## Android-facing decision

公開surfaceは次の固定codeだけである。

| Code | Label | Meaning |
|---:|---|---|
| 0 | `UNKNOWN` | 入力、保証、quality、K1 stateのいずれかがdecisionに不足 |
| 1 | `USUAL` | K1 pathを通過したがpermit threshold未到達 |
| 2 | `SLIGHTLY_DIFFERENT` | K1がpermitを内部発行済み |

score、p-value、baseline値、raw feature、exact timestamp、reject詳細は返さない。

## Permit confinement

K1が発行した`EvidencePermit`はbridge内部の`pending_permit`へ移動し、現在の公開APIから取り出せない。これはpermitを捨てるためではなく、後続のprovenance lease guardとATv2 issuerを同じtrusted pathへ追加するための封じ込めである。

`has_pending_internal_permit`はboolean診断だけを返し、permit内容、policy hash、epoch、slotを公開しない。

## Fail-closed behavior

- bad/unknown qualityはK1を進めない
- disconnected/incomplete acquisitionはwindow自体を生成しない
- session mismatchはK1を進めない
- phase mismatchはK1を進めない
- schema mismatchはK1を進めない
- K1 rejectまたはbaseline/context unavailableは`UNKNOWN`
- threshold/persistence未到達は`USUAL`

このbridgeはAndroid attestation、provenance evidence、NPL1 lease、ATv2発行をまだ行わない。
