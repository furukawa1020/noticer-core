# Private Acquisition Contract

## 目的

`noticer-acquisition-core`は、Replayまたはlive collectorから受け取ったPPG/ACCをHigh Sideに閉じ込め、後続処理へ渡す前に形状、時刻、設定、メモリ上限を検査する。

このcrateはセンサー真正性を証明しない。特に、通常のPolar BLE接続をsensor-signed sampleとして扱わない。

## Private batch

`PrivatePpgBatch`と`PrivateAccBatch`は次の制約を持つ。

- raw sample fieldはprivate
- raw sample getterを公開しない
- `Serialize`を実装しない
- `Debug`はsampleとtimestampを`REDACTED`にする
- 空batch、過大batch、次元不一致、period不一致、timestamp overflowを拒否する
- drop、eviction、disconnect、fault時に所有bufferを上書きしてから破棄する

公開されるのは、検証済みのframe/sample数とnegotiated settingsだけである。後続のfeature extractorは同じcrate内のprivate accessを使い、raw値を公開APIへ戻さない。

## Session分離

各`AcquisitionSession`は開始時に次のいずれか一つへ固定する。

- `Reference`
- `Calibration`
- `Monitoring`

phaseを途中変更するAPIは設けない。別phaseへ移る場合は別の`SessionId`で新規sessionを作る。これによりreference、calibration、monitoringのraw transcriptが暗黙に混ざらない。

## 時刻検査

PPGとACCは独立したclock trackを持ち、各batchのdevice timeとhost monotonic timeについて次を検査する。

- 同一timestampの再送
- deviceまたはhost clockのrollback
- policy上限を超えるgap
- device deltaとhost deltaの許容値を超えるdrift

検査は候補clock state上で行い、全検査が成功した場合だけsessionへcommitする。不正batchはtranscript、clock、件数を変更しない。

## Bounded transcript

session configは保持batch数と保持sample数の両方に固定上限を持つ。新規batchを保持すると上限を超える場合は、最古のrecordを上書きしてからevictする。単一batchがsession sample上限を超える場合は受理しない。

disconnectまたはfaultではtranscriptとclock stateを消去し、そのsessionでの追加ingestを拒否する。

## Source assurance ceiling

| Source | 最大Source Assurance |
|---|---|
| deterministic replay | `SyntheticReplay` |
| Polar Verity Sense BLE collector | `PairedCommercialSensor` |

Polar adapterがデバイス名、BLE pairing、SDK経由の取得を確認しても、それだけで`SensorSigned`へ格上げしない。より強いsource assuranceには、センサー起点の検証可能な暗号学的証拠が別途必要である。

## 非主張

この段階ではfeature抽出、signal quality判定、EvidencePermit、Android attestation、provenance lease、ATv2発行を実装しない。これらは個別Issueでprivate acquisition境界へ順次接続する。
