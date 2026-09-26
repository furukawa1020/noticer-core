# K10 QuotientGuard runtime研究契約

Status: **FROZEN BEFORE RESULTS**  
Parent Issue: #479  
Contract: `configs/quotient_guard/k10_qg_research_v1.toml`

## 目的

QuotientGuardは、K9で検証されたrelease機構をstream処理中に実行し、action-equivalentなcounterfactual shadow historiesの公開trace関係をオンライン監視するcandidate runtime enforcement architectureである。

## 信頼境界

TCBはcertificate checker、private ingress、shadow executor、relation monitor、safe sink、canonical clockに限定する。transport、Polar adapter、application、Studio、renderer、wall clock、OS schedulerは信頼しない。hardware securityは`NOT_VERIFIED`である。

private stateはraw frame、正規化biometric event、private readiness、counterfactual history、shadow state、private randomnessを含む。外部へ出せるのはallowed action、release trace、observer profile、fault class、monitor verdict、certificate digest、runtime epochだけである。

## Fail-closed

binding不一致、relation violation、resource exhaustion、rollback、unknown fault、clock bound超過は`NO_RELEASE` sinkへ遷移する。自動復帰は禁止し、新しい検証済みcapsule、epoch増分、明示的public resetの3条件を要求する。

## 判定境界

`RUNNING_VALID`だけが成功である。resource/clock限界は安全性の証拠ではなくinconclusiveとする。Studio表示、CI成功、adapter接続、wall-clock一致だけではsecurity claimを認めない。

## Artifact境界

generated artifactは`artifacts/k10_quotient_guard/`へ出しGitへcommitしない。raw biosignal、baseline、private history/readiness、subject/device/stable identifier、key materialを含めない。

## 改訂

結果観測後のsilent editは禁止する。訂正は新version、旧version保存、変更理由、結果観測有無の開示を必須とする。
