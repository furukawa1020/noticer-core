# K7 generic reactive privacy corpus v1

## 目的

Noticer固有名やbiosignal domainに依存しない8 familyで、AQRS discoveryと独立checkerの適用範囲を検査する。notification、fixed-size release、public retry、private scheduler、medical alert、smart-home actuator、activity actuator、fault-tolerant alarmを同じcanonical case契約へ固定する。

このcorpusは実環境への一般化や性能を主張しない。有限のreactive privacy semanticsを再現可能に検査するための事前登録fixtureである。

## split

| family | split | 主な境界 |
|---|---|---|
| `generic_delayed_notification` | train | delayとsilence |
| `generic_fixed_size_release` | train | fixed sizeとcadence |
| `generic_public_retry` | train | public retry |
| `generic_private_scheduler` | development | private schedule erasure |
| `generic_medical_alert` | development | public alert context |
| `generic_smart_home_actuator` | held_out | actuator action |
| `generic_activity_actuator` | held_out | activity-dependent public context |
| `generic_fault_tolerant_alarm` | held_out | loss、retry、reconnect |

splitはfamily単位で`benchmark_family_registry_v1.yaml`へ拘束する。held-out 3件はauthor templateを持たず、development調整へ利用しない。

## execution boundary

各sourceはrestricted parser、canonical formatter、semantic type checkerを通り、family IDに閉じた有限`SynthesisProblem`へlowerされる。train/developmentのtemplateはsolver-independent product checkerで検証する。held-outは解を公開せず、probe candidateを使ってcheckerが決定可能なnormal formまでlowerできることだけを確認する。

YAMLと公開manifestはaggregate dimensionとdigestだけを持つ。private scheduleの値、利用者識別子、device識別子はartifactへ出力しない。
