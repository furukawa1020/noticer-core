# Identity Attack Evaluation Protocol v0.1

## Purpose

防御実装より先に攻撃のデータ契約、split、指標、成果物を固定し、後続方式を同じ条件で比較可能にする。

## Main Protocol

Identity attackは同一人物の異なるsessionをtrain、validation、testへ割り当てる。validationは正則化選択だけに使い、testをparameter選択に使わない。

## Weak Protocols

Window-random splitは隣接windowとsession signatureをtrain/testへ混在させ、identity性能を過大評価し得るため主要結果には使用しない。

## Negative Control

Permuted-label controlはfeaturesとsplitを固定し、train、validation、test内でsubject labelを独立に並べ替える。class distributionを維持したまま本人性との対応だけを破壊する。

## Non-Claim

Synthetic smoke testの高いidentity accuracyは、実PPGから同じ精度でidentityを推定できることも、privacyの欠如も証明しない。これはharnessのengineering testである。

## Reproducibility

Config、seed、設定hash付きrun ID、window単位split manifest、予測、class probability、metricsを保存し、攻撃条件と結果を追跡可能にする。

## Future Dataset Adapters

WESAD、CASE、real wearable streamは、今後同じ`WindowDataset` contractへ接続する。dataset本体と個人データはartifactにもGitにも含めない。
