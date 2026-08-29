# K8-16a Performance Measurement Contract v1

## 目的

QuotientSealのperformance・resource costをsecurity verdictから分離して記録する。K8-16aは測定契約だけを固定し、実compiler、実engine、実hardwareの性能値は主張しない。

## Typed measurement

stageはcompile、parse、extract、validate、context check、capsule encode/check、runtime、QuotientPad、attack evaluationを区別する。metricとunitは次の固定対応を持つ。

| Metric | Unit |
|---|---|
| `WALL_CLOCK_TIME` | `NANOSECONDS` |
| `LOGICAL_FUEL` | `FUEL_UNITS` |
| `HOST_CALL_COUNT` | `COUNT` |
| `MEMORY_ACCESS_COUNT` | `COUNT` |
| `ARTIFACT_SIZE` | `BYTES` |
| `PEAK_MEMORY` | `BYTES` |
| `ATTACK_SCORE` | `SCORE_MILLIONTHS` |

failureとinconclusiveは数値valueを持たない別variantである。unsupported、resource bound、timeout、metadata欠落、checker disagreement、wall-clock非opt-inを0 costへ変換しない。

## Wall-clock境界

wall-clock sampleはconfigの明示opt-in、`OPT_IN_LOCAL_WALL_CLOCK` provenance、monotonic timer metadataの3条件をすべて要求する。wall-clock timingはmicroarchitectural proof、constant-time proof、RAQTR/AETP security proofではない。hardware statusは常に`NOT_VERIFIED`である。

## Metadata最小化

machine metadataはOS family、architecture、CPU数bucket、memory bucket、timer kind、公開software profile digestだけを保持する。hostname、username、filesystem path、machine serial、raw private biosignal、stable subject identifierを保持するfieldは設けない。benchmark case IDは公開fixture aliasであり、subject IDではない。

## Artifact

sampleとcampaignは別domainのSHA-256を持ち、sample key重複、digest collision、unit mismatch、iteration/sample bound、non-canonical JSONをfail-closedにする。fixture artifactは`INJECTED_TEST_FIXTURE`または`SOFTWARE_FIXTURE`と明記し、実世界性能値へ読み替えない。
