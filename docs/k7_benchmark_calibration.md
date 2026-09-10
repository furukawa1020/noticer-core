# K7 expected status・difficulty校正

## 目的

K7-08fは、authorが付与した期待ラベルを実行結果で自動修正せず、synthesizerと独立checkerの二経路で監査するfail-closed契約である。対象は24 familyすべてだが、held-out 8件は次段の開封ledgerが成立するまで`SEALED_HELD_OUT`として扱う。

## 固定境界

`configs/quotient_forge/benchmark_calibration_v1.yaml`は、各familyをcase SHA-256、AQRS SHA-256、spec-family split、期待status、difficulty vectorへ束縛する。difficulty vectorは実験前に利用できる公開dimensionだけから導出する。

- stateとhorizonは探索区間の下限・上限を分ける
- observer数と観測dimensionを分ける
- failure、retry、bounded loss、reconnectをfault axisとして数える
- 実測した最小state・最小horizonはengine observationにのみ記録する
- held-outの実測最小値は開封前に記録しない

探索上限は全case共通policyとして固定する。time limit、candidate limit、checker node limit、checker depth limitは別statusであり、いずれも`INCONCLUSIVE`である。`UNSAT_AT_BOUND`や`INVALID_SPEC`へ変換してはならない。

## 二重判定

calibration-scopeの各caseは、異なる`engine_id`を持つprimary observationとindependent observationを必要とする。

- 両方が固定期待値と一致した場合だけ`AGREE`
- engine間不一致、期待値との差、最小値の差は`DISAGREEMENT`
- 片方でもresource limitなら`INCONCLUSIVE`
- disagreement時に期待statusを上書きしない
- held-out observationを渡した場合はreportを生成せず拒否する

Rust integration testは、公開済みtrain/development witnessを独立checkerへ通し、bounded negativeをsynthesisとcheckerの両方で反証し、invalid specをdiagnosticで分離する。これはheld-out discovery結果ではない。

## Artifact

観測入力を用意した後、次でcanonical reportを`artifacts/`配下へ生成する。

```bash
python -m noticer_core.evaluation.benchmark_calibration \
  --config configs/quotient_forge/benchmark_calibration_v1.yaml \
  --observations artifacts/quotient_forge/calibration/observations.yaml \
  --output artifacts/quotient_forge/calibration/report.json
```

reportはconflicting replacementを拒否し、private biosignal、stable identifier、token、鍵素材を含めない。生成reportはGitへcommitしない。

## 非主張

- boundedな`UNSAT_AT_BOUND`はunbounded unrealizabilityを意味しない
- author templateの検証はminimality proofではない
- `PREOPEN_READY`はheld-out評価完了を意味しない
- hardware statusは`NOT_VERIFIED`である
- この校正契約だけで新規性、完全性、deployment一般化を主張しない
