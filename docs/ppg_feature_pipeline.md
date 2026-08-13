# Deterministic PPG/ACC Feature Pipeline

## Scope

`noticer-ppg-features`は、4秒windowと2秒strideでPPG/ACCから固定順序のprivate featureを生成する。Foundation Model、学習済みembedding、外部APIは使用しない。

このpipelineは透明性と再現性を優先したTier A実装である。`EmpiricalSpoofRisk`は既知fixtureに対する経験的indicatorであり、genuine human、特定人物、特定センサーを証明しない。

## Window contract

- window: 4 seconds
- stride: 2 seconds
- time basis: PPG device time
- minimum PPG completeness: 95%
- output timing: logical ordinalのみ
- exact PPG/ACC timestamp: privateのまま

ACC frameはPPG windowの開始・終了時刻に合わせて選択する。PPGの完全な4秒分がまだ到着していない場合はwindowを進めない。完全な時間範囲が到着していてsampleが欠落している場合はfeatureを生成するが、95%未満を`Bad`とする。

## Schema

`noticer.ppg-acc.v1`は44次元で、順序を公開定数として固定する。

| Group | Count | Content |
|---|---:|---|
| per-channel PPG | 24 | mean、standard deviation、range、lag-1 correlation、zero crossing、high-frequency energy |
| cross-channel PPG | 6 | 4 channelのpairwise correlation |
| ACC | 5 | axis standard deviation、motion RMS、jerk RMS |
| stream integrity | 4 | PPG/ACC completeness、gap ratio、clock drift ratio |
| quality indicators | 5 | flatline、saturation、ambient、motion、drift |

不足channelまたはACCなしの値は固定位置を維持するため0とし、qualityを`Unknown`へ落とす。出力値は全て有限値でなければならず、非有限値が生じたwindowはfail closedで拒否する。

## Quality semantics

| Quality | Meaning |
|---|---|
| `Unknown` | PPGは利用可能だがACC等のquality根拠が不足 |
| `Bad` | completeness不足、flatline、saturation、ambient contamination、clock/signal driftのいずれか |
| `Usable` |主要signal gateは通るがmotion/jerkが大きい |
| `Good` | 現在の決定的gateを通過 |

`Good`はhuman authenticityではない。replayや高品質signal synthesisが同じ統計を作れる可能性を残す。

## Privacy boundary

acquisition coreだけがprivate transcriptからwindowを組み立てる。feature crateは借用raw sliceを一方向に処理し、`PrivateFeatureVector`を返す。公開結果にはraw sample getter、feature value getter、exact timestamp、Serialize実装を設けない。

## Falsification fixtures

unit/property testsはclean、flatline、saturation、ambient-dominant、high-motion、clock-drift、sample-loss fixtureを固定する。また同じ入力から同じ44値が得られ、accepted inputでは全値がfiniteであることを検査する。
