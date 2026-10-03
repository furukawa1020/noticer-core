# K7 Transport Cost Attack Audit

K7-14eは再計算済みlogical cost、platform profile digest、precommitted calibration digest、必須measurement軸を同時に検証する。

過小申告またはcost差し替え、profile substitution、単位混同、interval/artifact改ざん、欠測・順序変更を別categoryでfail-closedにする。

このauditはmeasurement sourceとの共謀やsimulator model自体の現実との差を検出できない。これらは成功時にも`residual_limits`へ保持し、security proofとは扱わない。
