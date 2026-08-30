# K8-16c Censored Statistics v1

## 目的

measurement campaignをstage、metric、unit、module family、compiler config、engine、provenanceで層別し、成功sampleの統計とfailure/inconclusiveの発生状況を分離して保存する。

## 成功sampleの統計

median、p95、p99は整数nearest-rank法で計算する。MADはnearest-rank medianからのabsolute deviationのnearest-rank medianとする。platform依存floating pointをcanonical artifactへ入れない。

effect sizeは明示されたbaseline/candidate group間のCliff's deltaをmillionthsで保存する。candidateがbaselineより常に大きい場合は`1000000`、常に小さい場合は`-1000000`となる。group欠落やsuccess sample不足は`INCONCLUSIVE`である。

attack AUCはpositive/negative labelをplanで公開module family aliasへ束縛し、pairwise orderingをmillionthsで保存する。同点はhalf creditとする。label欠落または単一classは`INCONCLUSIVE`であり、AUC 0や0.5へ補完しない。

## Censored outcome

failureとinconclusiveはpercentile、MAD、effect size、AUCの数値入力へ混ぜない。一方でgroupごとのtotal、success、failure、inconclusive件数とreason histogramへ必ず残す。したがって成功sampleだけを見てfailure率を隠すことはできない。

## Artifact境界

source campaign digest、group順序、comparison plan、label registry、count整合性、scaled statistic範囲を完全再計算する。同じcampaignの二重投入、sample digest重複、plan key重複、tamperをfail-closedにする。fixture統計は実世界performanceやsecurity proofではなく、hardwareは`NOT_VERIFIED`である。
