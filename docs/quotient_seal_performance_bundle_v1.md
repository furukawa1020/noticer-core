# QuotientSeal Performance Reproduction Bundle v1

## 目的

K8-16eは、K8-16aからK8-16dまでの測定契約、deterministic software fixture、censored outcome対応統計、overhead budget gateを、独立検証可能な1つの再現bundleへ固定する。

これは実機性能の主張でも、security verdictでもない。標準exampleが生成する証拠由来は`SOFTWARE_FIXTURE`、実機状態は`NOT_VERIFIED`、解釈境界は`NOT_A_SECURITY_VERDICT`である。

## Bundle内容

`PerformanceReproductionBundle`は次を型付きで内包する。

- baselineの`FixtureRunArtifact`
- candidateの`FixtureRunArtifact`
- baselineの`StatisticsArtifact`
- candidateの`StatisticsArtifact`
- 両統計を入力とした`PerformanceGateArtifact`
- fixture、統計、gateのSHA-256参照
- warmupとは分離されたsuccess、failure、inconclusive件数
- gateの`PASS`、`FAIL`、`INCONCLUSIVE`件数
- bundle全体のdomain-separated SHA-256

統計はgate内部にも埋め込まれる。重複を省略せず完全一致を要求することで、外部ファイルの差し替えや「同名の別統計」を参照する余地をなくす。

## 検証するリンク

検証時は子artifact自身の再計算に加え、次を照合する。

1. baseline/candidateが同じfrozen fixture planを使う
2. 両runのsanitized machine metadataが一致する
3. provenanceが両方とも`SOFTWARE_FIXTURE`である
4. 各統計のsource campaign SHAが対応するfixture campaignと完全一致する
5. gateへ埋め込まれたbaseline/candidate統計がbundle直下の統計と完全一致する
6. summary件数と全SHA参照を子artifactから再導出できる
7. bundle全体のdigestがcanonical JSONから再計算できる

いずれかが不一致なら、部分的な結果を表示せずbundleを拒否する。

## 再現方法

repository rootで次を実行する。

```bash
cargo run -p quotient-seal-performance --example performance_bundle -- artifacts/quotient_seal/performance/performance_bundle.json
```

同じ場所へ次が生成される。

- `performance_bundle.json`: machine-readable canonical artifact
- `performance_bundle.md`: bundleだけから生成したhuman-readable report

出力先をdirectoryで指定した場合は`performance_bundle.json`と`performance_report.md`を生成する。既定値と実験条件の人間可読manifestは`configs/quotient_seal/performance_bundle_v1.yaml`にある。

`artifacts/`以下はGitへcommitしない。

## Reportの読み方

reportは再現リンク、censored outcome、ルール別candidate値、baseline値、増分、相対倍率、三値判定を表示する。日時やホスト名など再現性を壊す値は自動挿入しない。

`PASS`は宣言済みperformance budget内という意味だけを持つ。AETP、非干渉性、robustness、実機性能、microarchitectural securityの証明として引用してはならない。failureとinconclusiveも平均値へ補間せず、件数と理由を元artifactに保持する。

## 実機campaignへの拡張境界

実機値を扱う将来拡張では、K8-16aの明示opt-in wall-clock契約とsanitized metadataを使い、software fixture bundleとは別schemaまたは明示的なprovenance分岐を設ける。Polar Verity Senseを接続していない現段階では、実機検証済みと表示してはならない。
