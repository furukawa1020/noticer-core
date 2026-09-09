# K7 Noticer benchmark corpus v1

## 範囲

K7-08cは、K7-00で事前登録したNoticer系8 spec familyをcanonical AQRS caseへ固定する。各familyはAQRS sourceとprivacy-safe YAML envelopeの組であり、source digest、有限次元、split、feature tag、utility obligationを相互拘束する。

これはdeployment性能の実験結果ではない。8件はbounded semanticsとattack surfaceの回帰corpusであり、実世界biosignalや人物識別子を含まない。

## familyとsplit

| family | split | 主な境界 |
|---|---|---|
| `noticer_aets_fixed_cadence` | train | timing、size、silence |
| `noticer_aplot_bounded_loss` | train | bounded loss、retry、failure |
| `noticer_atv2_action_window` | train | action window、exactly-once |
| `noticer_aepa_public_context` | development | public context分岐 |
| `noticer_service_separation` | development | service別observer |
| `noticer_reconnect_normalization` | development | disconnect/reconnect正規化 |
| `noticer_multiservice_collusion` | held_out | observer coalition |
| `noticer_longitudinal_handoff` | held_out | serviceをまたぐlongitudinal observer |

splitは`benchmark_family_registry_v1.yaml`と完全一致しなければtestで拒否する。variantは全件`canonical`で、row random splitは存在しない。

## checker path

各AQRS sourceは次を通る。

1. restricted parser
2. canonical formatterとのbyte一致
3. secrecy・semantic type checker
4. family IDに閉じたdeterministic `SynthesisProblem` lowering
5. `SynthesisProblem::lower_candidate`
6. solver-independent bounded product checker

train/developmentの6件にはcanonical release machineのdigestをbindし、そのmachineがcheckerで`Verified`になることを検査する。held-out 2件はauthor templateを公開せず、解を使わないprobe candidateがcheckerの決定可能境界までlowerできることだけを検査する。

## privacy boundary

YAMLはaggregate dimensionとdigestだけを保持する。AQRS sourceはprivate fieldの型名を宣言できるが、private history値、raw PPG/IBI、subject ID、device IDは保持しない。生成manifestにもAQRS source本文を埋め込まない。
