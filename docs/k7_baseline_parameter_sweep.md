# K7 Baseline Parameter Sweep

K7-13fは、AQRSと比較baselineのparameter選択を再現可能にし、不利な候補だけを除外する比較を拒否する。これはsecurity proofではなく、比較手続きの契約である。

## 固定する境界

- 候補集合、source、version、privacy notion、selected configはbaseline comparison manifestへ事前登録する。
- 全候補を`development`と`held_out`の両方で測定する。欠落、重複、manifest外候補はfail-closedとする。
- config選択に使えるのは`development`だけである。`held_out`値を変えても選択結果は変化しない。
- 選択は`failure`、`attack`、`latency`、`bandwidth`、`state`、config digestの順に、小さい値を優先する決定論的な辞書式比較である。
- manifestの`selected_config_sha256`と再計算結果が一致しなければartifactを生成しない。

## Report semantics

reportはattack成功率、帯域量、failure数、latency、state量を独立した生値として保存する。合算score、privacy notionを跨ぐ順位、security proofという解釈は禁止する。異なるprivacy notionは別sectionへ分離する。

固定policyは`configs/quotient_forge/k7_baseline_sweep_v1.yaml`、Python APIは`noticer_core.evaluation.baseline_parameter_sweep`にある。`write_report`はcanonical JSONをUTF-8で出力し、`report_digest`は同一入力に対して同一SHA-256を返す。生成したreportは`artifacts/`配下へ置き、Gitへcommitしない。
