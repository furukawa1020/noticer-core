# ATv2 Adversarial Evaluation Bundle v1

## 目的

この文書はIssue #172で固定する、ATv2 P0 QSMのreconnect、loss、deadline、reset、handoff、resource境界に対するcanonical adversarial matrixと再現bundleの契約を定義する。

評価対象はIssue #171のsource expectation、QuotientSeal small-step、wasmi、Wasmtimeである。private biosignal、token bytes、claim、evidence、baseline、鍵は入力に含めない。

## Canonical matrix

各caseはdeterministic seedと全axisのcanonical encodingからcase IDを導出する。列挙順、thread scheduling、filesystem pathはcase IDへ影響してはならない。

scenario axisは次を含む。

- cover frame
- action frame
- deadline slot境界
- reset後のtick
- handoff後のtick
- 未知のservice/slot組

host fault axisは`NONE`、`TIMEOUT`、`RECONNECT`、`LOSS`を区別する。resource axisは`NOMINAL`、`FUEL_EDGE`、`MEMORY_EDGE`、`HOST_CALL_EDGE`を区別する。

host faultとresource exhaustionは別の原因・termination classである。どちらもMATCHへ自動昇格せず、相互に読み替えない。

## Trace invariants

すべてのcaseで次を監査する。

- ciphertext shapeは236 bytes
- cadenceはsource artifactの公開scheduleへ束縛される
- cover/actionは同じ`emit_frame`経路を使う
- action semanticsはaction frameだけに存在する
- resetはcursorをcanonical初期値へ戻す
- handoffは公開cursorだけを返す
- deadlineは独自exportではなく公開tick slot境界として評価する

fault注入によってframe長やcadenceを変更してはならない。resource exhaustionで評価を完走できない場合は`UNRESOLVED`であり、privacy successではない。

## Deterministic execution

matrix caseはIssue #171のcanonical context sequence、host tape、execution limitsへloweringする。同じcase、module、engine digestから生成するparticipant artifactはbyte-identicalでなければならない。

各caseは次を保存する。

- source/frame-plan/module/capsule digest
- seedとcase ID
- scenario、host fault、resource axis
- context command列とhost tape
- source expectation
- small-step、wasmi、Wasmtime artifact
- aggregate verdict
- first typed differenceまたはunresolved reason

## Counterexample shrink

COUNTEREXAMPLEはcanonical順序で縮約する。

1. witnessより後のcommandを除去する。
2. first differenceへ寄与しないcommandを除去する。
3. difference signatureを保つ範囲でresource limitを縮小する。
4. witnessに不要なhost outcomeを`Continue`へ正規化する。

各試行は操作、candidate digest、判定、採否をtranscriptへ保存する。縮約後もdifference origin、observable axis、participant、termination class、first typed differenceが一致しなければならない。

## Reproduction bundle

bundleはoriginal input/artifact、minimized input/artifact、matrix case、shrink transcript、first typed difference、engine digestを相互束縛する。bundle verifierは全digestを再計算し、同じ入力からbyte-identical bundleを再構成できなければ拒否する。

テスト目的で注入した差分は`TEST_INJECTION_NOT_SCIENTIFIC_RESULT`と明示する。injected mismatchを実機、実network、実攻撃の科学的結果として報告してはならない。

## 非主張

- hardware status: `NOT_VERIFIED`
- P1 equivalence: `NOT_VERIFIED`
- 実BLE controllerまたは実radioでの同値性: `NOT_VERIFIED`
- 文献・特許上の優先権またはworld-first: 主張しない

このbundleはsoftware P0 evaluationの再現性を固定するものであり、hardware証明ではない。

No world-first claim is made by this software evaluation bundle.
