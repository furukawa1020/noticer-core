# QuotientSeal Overhead Budget Gate v1

## 目的

K8-16dは、QuotientSealのbaselineとcandidateの性能統計を、事前に宣言した予算へ機械的に照合する回帰ゲートである。ゲートの`PASS`は性能予算内であることだけを意味し、セキュリティ性、秘匿性、実機性能を証明しない。成果物はこの境界を`NOT_A_SECURITY_VERDICT`と`NOT_VERIFIED`で明示する。

このゲートはwall-clock値を暗黙に取得しない。入力はK8-16cの正規化済み`StatisticsArtifact`であり、通常の再現試験ではK8-16bのdeterministic software fixtureから生成する。

## 判定単位

各ルールは次の完全なselectorで統計群を指定する。

| 項目 | 意味 |
|---|---|
| `stage` | compile、runtime、capsule encodeなどの測定段階 |
| `metric` | logical fuel、artifact size、failure rateなどの測定量 |
| `unit` | fuel units、bytes、countなどの単位 |
| `case` | benchmark case名 |
| `provenance` | software fixtureなどの証拠由来 |
| `statistic` | median、p95、p99、MAD、failure rate、inconclusive rate |

単位を含む完全一致を要求する。同じ測定対象に異なる単位の群しか存在しない場合は、暗黙の換算をせず`UNIT_MISMATCH`とする。

## 予算制約

### AbsoluteMaximum

candidate統計値が`limit`以下なら`PASS`、超えれば`FAIL`とする。上限値と等しい場合は`PASS`である。

### AbsoluteIncreaseMaximum

`max(candidate - baseline, 0)`が`limit`以下なら`PASS`とする。candidateが改善した場合の増分は0として扱い、負数や符号付きオーバーフローを導入しない。

### RelativeMaximum

`candidate / baseline`を百万分率の整数として半分切り上げで計算し、`ratio_millionths`以下なら`PASS`とする。例えば110%は`1_100_000`である。baselineとcandidateがともに0なら比率を`1_000_000`とする。baselineが0でcandidateが正の場合、意味のある比率を定義できないため`ZERO_BASELINE`の`INCONCLUSIVE`とする。

## 三値判定

| 判定 | 条件 |
|---|---|
| `PASS` | 比較可能であり、宣言済み予算内 |
| `FAIL` | 比較可能であり、宣言済み予算を超過 |
| `INCONCLUSIVE` | 比較に必要な証拠が不足または不整合 |

ルール集合の最終判定は`FAIL`を最優先し、次に`INCONCLUSIVE`、最後に`PASS`とする。したがって、比較不能な測定を成功扱いにすることも、明確な予算超過を比較不能で隠すこともできない。

`INCONCLUSIVE`となる条件は次のとおりである。

- candidateの統計群が存在しない
- baselineの統計群が存在しない
- selectorと入力統計の単位が一致しない
- median、p95、p99、MADを出すための成功sampleが不足する
- 相対比較のbaselineが0でcandidateが正である
- 安全な整数演算の範囲を超える

## Censored outcome

failureとinconclusiveは成功sampleへ補間しない。それぞれの件数と理由histogramをK8-16cの統計成果物に残し、必要に応じて百万分率の独立した予算へ照合する。率の分母は同一群のsuccess、failure、inconclusiveの総数である。

## 再現性と改ざん検出

`PerformanceGateArtifact`は次を自己完結で保持する。

- digest付き`BudgetPlan`
- baselineの`StatisticsArtifact`
- candidateの`StatisticsArtifact`
- 各ルールの入力値、差分、比率、判定理由
- 集約した三値判定
- `NOT_A_SECURITY_VERDICT`
- `NOT_VERIFIED`
- 成果物全体のSHA-256 digest

検証時には埋め込まれたplanと統計から評価を再計算し、保存済み評価およびdigestと照合する。同一の正規入力はbyte-identicalなcanonical JSONを生成する。

## 設定例

宣言例は`configs/quotient_seal/overhead_budget_gate_v1.yaml`に置く。このYAMLは予算レビュー用の人間可読manifestであり、測定結果そのものではない。ローカル実機値を追加する場合も、明示的なopt-in、timer種別、sanitized machine metadataをK8-16aの契約に従って記録し、実機確認前に`VERIFIED`へ変更してはならない。
