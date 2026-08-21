# AEPA P0 Three-Engine Differential Evaluation v1

## 目的

この文書はIssue #191で固定するAEPA P0 QSMの差分評価契約を定義する。対象engineはsmall-step reference、wasmi、Wasmtimeの三系統である。

評価はsource-derived reference traceとsmall-step実行のrefinementを先に確認し、その後small-step、wasmi、Wasmtimeの公開observable traceとterminationを比較する。engine disagreement、parser unsupported、fuel、host-call、memoryなどのresource不足を成功へ格上げしない。

## 公開sequence

各public callはservice alias、連番public step、AEPA public input codeだけを持つ。public input codeはprivate evidenceではない。VALIDATED_ADMISSIONは既存trusted pathの検証後に生成される公開symbolであり、lease bytes、nonce、appraisal、biosignalをsequenceへ含めない。

reset、handoff、stopは固定lifecycle commandとして扱う。resetはstateとcursorを初期化し、handoffはcursorを返してstateをWAITINGへ戻す。command後にはpublic statusを観測し、state digestをtraceへ記録する。

## Source refinement gate

Issue #187の36遷移tableをartifact内で再計算し、source digestとtransition digestへ束縛する。source referenceは同じtableからemit frame、admit-once action、reject、fault、reset、handoffを導出する。

source referenceとsmall-stepの共有public inputが異なる場合はartifactを拒否する。どちらかが未実行ならUNRESOLVEDとし、observableまたはterminationが異なればCOUNTEREXAMPLEとする。両者が一致した場合だけsource refinementをMATCHとする。

## Three-engine oracle

三系統の完全なEngineRunArtifactをDifferentialOracleへ渡す。比較軸はAPI call・return、host import、frame、action、public failure、reset、handoff、public state、termination、resource exhaustionである。

最終判定は次の三値を保つ。

- MATCH: source refinementと三engine oracleの両方がMATCH
- COUNTEREXAMPLE: いずれかにfirst typed differenceがある
- UNRESOLVED: parser、engine、resource、source referenceのいずれかが未完了

UNRESOLVEDをMATCHまたはsecurity successとして数えない。

## Injected fixtureの表示

target-only admissionや余剰host callを検出するnegative controlは、evidence originをINJECTED_TEST_FIXTURE、injection labelを必須とする。注入したtraceを実engineから得た科学的counterexampleとして表記してはならない。

通常実行artifactはEXECUTED_SOFTWAREだけを名乗る。いずれも実端末、Polar、Android attestation、hardware-backed keyの検証ではなく、hardware statusはNOT_VERIFIEDである。

## 非主張

P1 resource trace equalityはIssue #190までNOT_VERIFIEDである。replay、expiry、downgradeのadversarial completenessはIssue #189までNOT_VERIFIEDである。

この成果物はcandidate evaluation mechanismであり、文献・特許上の優先権またはworld-firstを主張しない。
