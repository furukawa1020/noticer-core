# APLOT Adversarial Reproduction Bundle v1

## 目的

この文書はIssue #180で固定するAPLOT adversarial matrix、三系統実行artifact、counterexample shrink、full recomputation bundleの契約を定義する。

matrixはdeterministic 32-byte seed、Issue #178のsource/module/capsule/ABI digest、scenario・host・resource axis、公開commands、execution limitsをcase IDへ束縛する。同じ入力からcase順、canonical bytes、matrix digestがbyte-identicalでなければならない。

## Scenario axis

15種を固定する。

- normal
- sourceで宣言済みのlossとreconnect
- host-injected timeout、reconnect、loss
- duplicate public step
- capacity boundary
- secret retry attempt
- resetとhandoff
- deadline前・同時・後
- unknown service

application retry commandは存在しない。secret retry attemptは同じpublic stepの余分な再呼出しとして表現し、追加`qseal.emit_frame`が観測された場合をcounterexampleとする。`ContextFamily::Retry`自体はcanonical matrixへ入れず、構築時に拒否する。

capacity boundaryはP0 resource axisとして評価する。実BLE reassemblerのcapacity equivalenceを証明するものではない。

## Faultとresourceの分離

host faultはtimeout、reconnect、loss、terminateを最初のcanonical host importへ注入する。fuel、memory page、host-call上限はresource axisとして別に保存する。

parser failure、timeout、resource exhaustion、engine failureをMATCHへ格上げしない。fault trapとresource exhaustionは異なるtyped terminationとして保持する。

## Counterexample shrink

counterexampleだけを次の固定順で縮約する。

1. command suffixを落とす
2. 公開faultを0へ戻す
3. fuelを縮小する
4. memory page上限を縮小する
5. host-call上限を縮小する

各attemptは候補input digest、operation、結果を保存する。originalとminimizedは同じfirst typed difference signatureを再現しなければならない。bundle検証は格納済みverdictを信頼せず、matrix binding、input、実行結果、shrink履歴をfull recomputationする。

## 実験上の注意

testで意図的にengine traceを変異させて作るmismatchは、shrink・reproduction harnessの検証用instrumentationである。科学的な脆弱性発見、実engine defect、実radio攻撃成功として報告してはならない。

## 非主張

- matrix外のadversarial completeness: `NOT_VERIFIED`
- real BLE controller equivalence: `NOT_VERIFIED`
- radio timing equivalence: `NOT_VERIFIED`
- hardware status: `NOT_VERIFIED`
- 文献・特許上の優先権またはworld-first: 主張しない

これはbounded declared matrixのcandidate evaluation bundleであり、hardware・実radio実験の結果ではない。
