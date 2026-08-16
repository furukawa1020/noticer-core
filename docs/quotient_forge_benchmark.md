# QuotientForge benchmark・attack・scalability評価protocol

## Scope

K6-12は、QuotientForge評価harnessの配線、split、metric、timeout、ablation、artifact契約を
固定するsynthetic protocol smokeである。生成値をNoticerのdeployment性能、実biosignal上の
privacy保証、または新規性の実証として扱ってはならない。

## Case catalog

catalogは次の11 caseを固定する。

- Noticer 4件: AETS fixed cadence、APLOT bounded loss、ATv2/Menfugu action window、AEPA public context
- Generic 4件: delayed notification、fixed-size release、public retry、service separation
- Unrealizable 3件: authorized output欠落、deadlineに対するstate bound不足、fault recovery output欠落

各caseについて、bounded schedule候補をstate数、release slot、release widthの順で列挙する。
securityとutilityを満たす候補からcost最小を選ぶため、caseごとのscheduleを直接選択する
handwritten selectorではない。保存metricはstatus、pointwise equality、security、utility、cost、
search node数、synthesis wall timeである。

## Counterfactual attack

実現可能な8 caseについて、各`counterfactual_pair_id`にworld 0とworld 1を作る。

- `quotient_forge`: pair内の全observable featureがpointwise equal
- `leaky_control`: release slot、packet count/size、interval、retry、service、action windowへ意図的にworld差を入れる

splitは`counterfactual_pair_id`を一度だけtrain/validation/testへ割り当てる。row random splitを
提供しない。dataset rowsはmodel入力にだけ使い、generated artifactへ保存しない。

攻撃器は次の4種に固定する。

- LogisticRegression + StandardScaler
- RandomForest
- ExtraTrees
- HistGradientBoosting

ROC-AUC、balanced accuracy、F1、attack advantage、fit/predict wall timeを保存する。
smoke acceptanceはprotected ROC-AUC最大0.60以下、leaky control最小0.90以上である。

## Scalabilityとtimeout

plant state、release machine state、horizon、observer、faultの5軸を個別に増加させる。
synthetic bounded product workloadを`timeout_work_units`まで実行し、次を保存する。

- requested work unitsとexecuted work units
- wall time
- deterministic checksum
- `COMPLETE`または`TIMEOUT`

これはsolverの絶対性能値ではなく、resource exhaustionをartifactへ欠落なく残すための
deterministic timeout smokeである。

## Ablation

full systemから次の6機構を1つずつ除去する。

- quotient
- symmetry reduction
- CEGIS blocking
- cost optimization
- repair
- independent checker

各rowはrealizable solved数、unrealizable rejected数、security/utility率、平均cost、search nodes、
synthesis timeを持つ。checker除去時はsecurityを推定でPASSにせず、未検証として0にする。

## Artifact contract

実行:

```bash
python tools/run_quotient_forge_benchmark.py \
  --config configs/quotient_forge/benchmark_smoke.yaml
```

出力は`artifacts/k6_quotient_forge_benchmark/`以下に生成し、Gitへcommitしない。

- `case_results.csv`
- `pointwise_equality.csv`
- `split_manifest.csv`
- `attack_results.csv`
- `scalability.csv`
- `ablations.csv`
- `summary.json`
- `feature_schema.json`
- `run_config.json`
- `run.log`
- `public_artifact_validation.json`

raw PPG、個人baseline vector、stable identifier、subject/device identifier、private history、
exact acquisition timestampを保存しない。public validatorが全JSON/CSV/logを検査し、違反時は
runを失敗させる。
