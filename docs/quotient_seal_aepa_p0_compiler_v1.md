# AEPA P0 QSM Compiler v1

## 目的

この文書はIssue #187で固定する、AEPA public admission sourceからP0_PUBLIC_QUOTIENT_ONLY Quotient-Sealed Moduleへの決定的lowering契約を定義する。入力はIssue #188で固定したcanonical source artifactとK7 bindingだけである。

compilerはprivate appraisal、EvidencePermit、provenance lease bytes、lease nonce、biosignal、baseline、collector session key、attestation chainを受け取らない。既存K5 trusted pathが検証した後の公開symbolだけを扱う。

## Canonical transition lowering

4状態と9公開入力の直積にある36遷移を、source state code、public input codeの順で整列する。各lowered recordはsource state、public input、next state、public outputを保持する。この36 recordのdigestをcompiler manifestへ入れ、同じrecordからWasmを生成する。

compile時に、source artifactの全遷移とlowered recordを一対一で照合する。欠損、重複、余分な遷移、next stateまたはoutputの不一致は成功へ格上げしない。この段階で主張するsource-target refinementは、この有限な36遷移のone-step対応に限る。

## P0 ABI

固定ABIは次の4 exportを持つ。

- qseal.public.tick(service, public_step, public_symbol) -> i32
- qseal.public.reset() -> i32
- qseal.public.handoff() -> i64
- qseal.public.status() -> i32

public_symbolはAEPAの公開入力codeであり、private evidenceではない。public_stepは0から単調に1ずつ進む。service、step、symbolが不正な場合はtyped public failureへ閉じる。

有効な全遷移でqseal.emit_frameを1回呼ぶ。ADMIT_ONCEだけは、K7 certificateに束縛された単一required actionをqseal.emit_actionへ渡す。REJECTとFAULTは固定codeのqseal.public_failureへ落とす。sourceのEXPIREDは公開deadline rejectionとして扱う。

resetはstateをWAITING、cursorを初期値へ戻す。handoffはcursorを返し、private machine stateを持ち越さずWAITINGへ戻す。source alphabet内のresetとhandoffもtotal transitionとして同じnext stateへloweringする。

## Artifact binding

成果物はsource、36遷移、K7 certificate、generated runtime、Wasm module、target IR、ABI、compiler manifest、capsule、observer registryのdigestを束縛する。Noticer registryのAEPA entryは同じsource、certificate、runtime、capsule、observer digestを持たなければならない。

service alias、pairwise alias、epoch、policy hash、NPL1 verifier key、pipeline measurement、assurance profile、ATv2 issuer key、public admission windowはcompiler manifestへ記録する。lease payloadやprivate resource traceは記録しない。

## Fail-closed境界

次はcompile成功ではない。

- K7 source digestの不一致
- service mappingの欠損、重複、未知alias、zero QSM code
- K7 required actionの欠損、複数化、i32範囲外
- state、input、transition、Wasm、capsuleのresource上限超過
- canonical P0 ABIまたはtarget IR loweringの失敗
- capsule decodeまたはregistry digest bindingの不一致

## 非主張

三系統engineによるtarget実行同値性はIssue #191までNOT_VERIFIEDである。P1 private resource trace equalityはIssue #190までNOT_VERIFIEDであり、このcompilerはP1を受理しない。実端末、Polar、Android attestation、hardware-backed keyもNOT_VERIFIEDである。

この成果物はcandidate compiler mechanismであり、文献・特許上の優先権またはworld-firstを主張しない。
