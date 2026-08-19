# ATv2 P0 Quotient-Seal Compiler v1

## 位置付け

この文書は、Issue #170で固定するAtypicality Token v2（ATv2）の公開source artifactから、`P0_PUBLIC_QUOTIENT_ONLY` Quotient-Sealed Module（QSM）への決定的lowering契約を定義する。

対象はK8-13c1で凍結した公開frame identity、cover/action区分、K7 certificate bindingだけである。token bytes、claim、evidence、baseline、鍵、暗号素材をcompilerへ入力してはならない。

本段階は候補primitiveのcompiler境界を固定するものであり、P1、hardware、transport adversaryに対する同値性を証明するものではない。

## 入力契約

compilerが受け取る入力は次に限定する。

- canonicalな`Atv2PublicSourceArtifact`
- source digestと一致する`Atv2K7Binding`
- service aliasから非ゼロのQSM service codeへの全単射
- 明示的なresource limits

各公開frameは、service alias、epoch、policy hash、public bucket、bucket内slot、sequence、absolute slot、cover/action区分だけを保持する。action frameは、同じservice aliasとpublic bucketを持つ公開action obligationへ一意に対応しなければならない。

## 決定的lowering

同じcanonical入力とlimitsから生成されるWasm、compiler manifest、certificate、capsuleはbyte-identicalでなければならない。callerがservice mappingを渡す順序は出力へ影響してはならない。

loweringは次の順序を固定する。

1. K7 source digest、service集合、mappingの全域性を検証する。
2. service alias順にmappingをcanonicalizeする。
3. frameをabsolute slot、service aliasの順に配置する。
4. cover/actionを同じ`qseal.emit_frame`経路へloweringする。
5. action frameだけを対応する`qseal.emit_action`へloweringする。
6. canonical P0 ABI、target IR、compiler manifest、certificate、capsuleを生成する。
7. capsuleをdecodeしてmodule、ABI、source、K7 certificate、runtime digestとのbindingを再検証する。

frame payloadは常に236 bytesであり、cadenceはsource artifactの公開scheduleに束縛される。frame kindによってciphertext形状や送出間隔を変更してはならない。

## 固定ABI

公開exportは次だけである。

- `qseal.public.tick(service: i32, slot: i64, fault: i32) -> i32`
- `qseal.public.reset() -> i32`
- `qseal.public.handoff() -> i64`
- `qseal.public.status() -> i32`

deadline専用exportはcanonical ABIに追加しない。deadlineは`tick`の公開slot境界とtyped public failureで表現する。これにより、ATv2固有exportを追加してABI fingerprintを分岐させない。

importは`qseal.emit_frame`、`qseal.emit_action`、`qseal.public_failure`だけである。private ingress import、memory import、任意host callbackは禁止する。

## 拒否条件

compilerは少なくとも次をfail closedで拒否する。

- K7 bindingとsource digestの不一致
- service mappingの欠落、重複、alias衝突、code `0`
- action frameと公開action obligationの不一致または多重対応
- frame、action、Wasm、capsuleのresource limit超過
- canonical P0 ABIから外れるmodule
- capsule decode後のdigestまたはmanifest binding不一致
- source、certificate、runtime、module、ABI digestの改変

## 成果物binding

compiler manifestにはcompiler ID、source digest、frame-plan digest、epoch、policy hash、service alias、frame bytes、frame interval、K7 runtime manifest、hardware statusを含める。

registry bindingはsource、K7 certificate、generated runtime、compiled capsule、observer registryを同時に束縛する。どれか一つでも差し替えたartifact setは受理しない。

## 検証境界

このIssueで確認するのは、決定性、canonical ABI、artifact binding、malformed mapping、tamper、resource rejectionである。

- small-step、wasmi、Wasmtimeの意味的一致: Issue #171で検証する
- reconnect、loss、deadline adversary: Issue #172で検証する
- P1 sealed admission equivalence: `NOT_VERIFIED`
- hardware equivalence: `NOT_VERIFIED`

したがって、この文書または生成artifactをhardware証明、transport robustness証明、世界初の断定に使用してはならない。
