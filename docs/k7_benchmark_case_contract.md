# K7 canonical AQRS benchmark case contract

## 目的

K7-08の全benchmark familyを、同じbounded AQRS semanticsへ接続するための公開envelopeを固定する。caseはprivate historyそのものではなく、AQRS sourceのdigest、有限の次元、攻撃面tag、utility obligation、期待する結果classだけを保持する。

この契約はautomatic discoveryの性能を主張するものではない。corpus実装、独立oracle、held-out開封、template equivalenceは後続Issueで行う。

## canonical fields

case YAMLは次のfieldだけを持つ。

- `schema`: `noticer.k7.aqrs-benchmark-case.v1`
- `family_id`, `variant_id`: lowercase `snake_case`。case IDは両者から`family_id__variant_id`として導出し、別名を受け取らない
- `split`: `train`, `development`, `held_out`
- `aqrs`: language versionとcanonical AQRS sourceのSHA-256だけを保持する
- `dimensions`: plant、machine bound、horizon、observerの有限次元
- `feature_tags`: timing、size、silence、retry、failure、collusion、longitudinalのsorted set
- `obligations`: action window、exactly-once、bounded loss、reconnectのsorted set
- `expected_outcome_class`: `REALIZABLE`, `UNREALIZABLE`, `INVALID`
- `difficulty_tier`: `D1`から`D5`
- `author_template_sha256`: optional binding。`held_out`では必ず`null`

unknown field、duplicate key、YAML anchor・alias・tag、非canonical ID、zeroまたは上限超過bound、未整列・重複setを拒否する。これにより`subject_id`、`device_id`、raw PPG/IBIなどをcaseや公開manifestへ追加できない。AQRS source自体もmanifestへ埋め込まない。

## digest

parserは受理した値をsorted-key compact JSONへ正規化し、末尾LFを付ける。case digestは次である。

```text
SHA-256("NOTICER_K7_AQRS_BENCHMARK_CASE_V1\\0" || canonical_case_bytes)
```

YAMLのfield順序やLF/CRLFが異なっても、同一caseのcanonical bytesとdigestは一致する。AQRS source bindingはBOMなしUTF-8、LF、末尾改行を要求し、そのbyte列のSHA-256を照合する。

## 既存AQRSとの境界

case envelopeは新しいsemantics DSLではない。後続corpus loaderは次の順序を守る。

1. Pythonのstrict case parserでenvelopeとresource boundを検証する
2. canonical AQRS sourceのdigest bindingを検証する
3. Rustの`quotient-forge-syntax::parse_module`でsourceをparseし、`format_module`の再適用でcanonical性を確認する
4. 既存`CompiledModel`または`SynthesisProblem`へlowerし、既存validator/checkerを通す

K7-08bは1と2の契約を固定する。3と4を迂回する独自benchmark semanticsは許可しない。

## artifact

`tools/build_k7_benchmark_case_manifest.py`はcaseを検証し、必要なら`--aqrs-source`を照合してcanonical JSON manifestを出力する。出力にはprivate biosignal field数、stable person identifier field数、AQRS source埋め込み有無を明示する。同じ内容への再実行はidempotentで、異なるmanifestによる上書きは拒否する。

generated manifestは`artifacts/`配下へ出力し、Gitへcommitしない。
