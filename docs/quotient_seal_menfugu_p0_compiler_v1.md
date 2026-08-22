# Menfugu P0 QSM compiler v1

## 目的

Issue #198では、K8-13f1で凍結したMenfugu公開実行semanticsを、`P0 Public Quotient Only`のQSMへdeterministicにcompileする。source、K7 certificate、generated runtime、Wasm module、target IR、ABI、compiler manifest、capsule、observer registryを1本の再計算可能なbindingへ接続する。

本実装は提案中のsecurity notionを支えるcompilerであり、world-firstを断定しない。物理pump、BLE、Polar Verity Senseの実機状態は`NOT_VERIFIED`である。

## Canonical lowering

入力は`MenfuguPublicSourceArtifact::canonical()`だけである。4状態と14入力の直積56遷移を`(state, input)`順へloweringし、欠落、重複、順序差、source digest差を拒否する。

`ExecuteOnce`を持つ遷移は`READY + AUTHORIZED_ACTION`の1件だけでなければならない。Wasmで`emit_action`を呼べるのもこのoutputだけである。replay、expiry、wrong service、wrong policy、wrong key、duplicateは`public_failure(REJECT)`となり、action host callを生成しない。

## Fixed public ABI

生成Wasmは次のhost callだけをimportする。

- `qseal.emit_frame`
- `qseal.emit_action`
- `qseal.public_failure`

exportは`tick`、`reset`、`handoff`、`status`の固定surfaceである。token ID、replay集合、raw biosignal、private baseline、EvidencePermit、nonce、attestationを受けるimport/exportは存在しない。ABI validatorでこのsurfaceをcompile時に検査する。

## Artifact chain

compilerは以下を順に生成・束縛する。

1. canonical lowered transition digest
2. fixed-ABI Wasm module digest
3. canonical target IR digest
4. public policyとK7 digestを含むcompiler manifest
5. relation certificate
6. QSM capsule digest
7. observer registry digest

K7 certificateとgenerated runtimeはopaque bytesとして扱うが、サイズ上限とdomain-separated digest一致を入口で必須とする。callerが宣言したdigestと1 byteでも異なるartifactはcompileしない。

## Registry binding

compiled binding時には、K8-13f1のmodule/service/epoch/policy/K7検査に加えて、Wasm、target IR、ABI、compiler manifest、capsule、observer registryをbytesから再計算する。registry entryのcapsuleまたはobserver digestだけを差し替えた状態もfail closedとなる。

## 検証範囲

自動テストはbyte-identical compile、全56遷移refinement、exactly-once lowering、K7 bytes tamper、resource limit、registry tamper、private ingress不在を確認する。

三系統engineでの実行等価性はIssue #199、adversarial exactly-onceはIssue #200、target-only counterexample bundleはIssue #201で扱う。それらは現時点で`NOT_VERIFIED`である。
