# QuotientSeal Studio Evidence Contract v1

## 目的

K8-17aは、native checkerが検証したQuotientSeal artifactとbrowser UIの間に、boundedかつallowlist方式の表示契約を置く。Studioは任意JSON viewerではなく、研究artifactの判定境界を保った説明面である。

browserへ渡せるのは、artifact kind、三値判定、SHA-256、provenance、hardware status、security interpretation、kind別の公開整数fact、digest link、固定diagnostic codeだけである。入力由来の自由文を表示しない。

## 対応する証拠kind

- `QSM_CAPSULE`
- `TRANSLATION_VALIDATION`
- `ADVERSARIAL_CONTEXT`
- `MUTATION_CAMPAIGN`
- `ENGINE_DIFFERENTIAL`
- `PERFORMANCE_BUNDLE`

各kindは固有のprovenanceと公開fact allowlistを持つ。例えばperformance bundleは`SOFTWARE_FIXTURE`および`NOT_A_SECURITY_VERDICT`としか結合できない。

## 三値判定

`VALID`、`INVALID`、`INCONCLUSIVE`を文字列置換やtruthy判定で変換しない。

- `VALID`はdiagnosticを持たない
- `INVALID`はdigest mismatch、relation divergence、capability violationなどのinvalidating codeだけを持つ
- `INCONCLUSIVE`はunsupported、resource bound、engine disagreement、parser disagreement、missing evidenceだけを持つ

したがって、unsupportedやresource exhaustionをbrowser上で成功へ変換できない。performanceの`VALID`も、security interpretationが`NOT_A_SECURITY_VERDICT`のためsecurity proofとして表示できない。

## Bounded parser

既定かつhard maximumとして次を制限する。

| 対象 | 上限 |
|---|---:|
| UTF-8 JSON | 512 KiB |
| depth | 12 |
| node数 | 4096 |
| array要素 | 512 |
| object key | 128 |
| string | 4096 bytes |

呼出側は上限を小さくできるが、hard maximumより大きくできない。危険なprototype key、未知schema、未知field、unsafe integer、invalid UTF-8はfail closedで拒否する。

## Private-data exclusion

`raw_biosignal`、PPG、IBI、ECG、personal baseline、secret/key、stable identifier、subject/participant/user IDに相当するfield名を再帰的に拒否する。公開factもkind別allowlistに限定し、値を整数、真偽値、nullへ制限する。diagnostic messageと画面titleは入力から受け取らず、review済みcodeからStudio側で導出する。

この境界は暗号化やnative artifact検証の代替ではない。browserへprivate biosignalまたはsecret keyを渡さないための追加防御である。

## 実機境界

v1は`hardware_status = NOT_VERIFIED`だけを受理する。Polar Verity Senseを接続していないfixtureを、実機確認済みへ昇格させない。将来の実機証拠は別versionの契約と明示的なprovenance reviewを必要とする。

## 検証

`npm run check`はNode 24のruntime testを先に実行し、その後Astro/TypeScript checkを行う。テストはdeterministic fixture、三値保存、secret field拒否、schema/digest/provenance不整合、byte/depth/array hard boundを対象とする。
