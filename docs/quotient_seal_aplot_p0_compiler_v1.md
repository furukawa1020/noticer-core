# APLOT P0 QSM Compiler v1

## 目的

この文書はIssue #178で固定するAPLOT公開transport sourceからP0 Quotient-Sealed Moduleへの決定的compile契約を定義する。

入力はIssue #177のcanonical source artifactとK7 bindingだけである。envelope、fragment payload、transport ID key、token plaintext、claim、evidence、baseline、private timestampをcompilerへ渡してはならない。

## Canonical transport event列

各公開frameを次のeventへ展開する。

- 20個の固定fragment attempt
- sourceで宣言された0個以上の公開reconnect event
- 1個の公開deadline event

eventはscheduled tick、event kind code、frame ordinal、fragment ordinalの順で整列し、0から始まるcanonical `public_step`を割り当てる。複数eventが同じscheduled tickを持っても、QSM ABIへ渡すstepは一意である。実tickはcompiler placementに残し、private clockを入力へ持ち込まない。

fragment attemptはdelivery成否にかかわらず`qseal.emit_frame`をちょうど1回呼ぶ。source loss maskでlostと宣言されたattemptは、その直後に固定codeの`qseal.public_failure`を呼ぶ。reconnectとdeadlineもsourceから決まる固定codeを使う。callerが渡す公開faultは、そのevent固有のhost call完了後にだけ評価する。

## 順序とretry境界

`qseal.public.tick`はservice aliasと次の`public_step`だけを受理する。欠落、重複、逆順、未知stepはfail closedとする。resetはcursorを初期値へ戻し、handoffはcursorだけを返す。

application retry countは常に0であり、retry event kind自体をtarget event alphabetへ持たない。loss、reconnect、deadline、host return、payload、verification結果によって追加fragmentを生成してはならない。

## P0 ABIとprivate ingress

Wasm importはP0 allowlist内の次だけを使用する。

- `qseal.emit_frame`
- `qseal.public_failure`

private import、非allowlist import、可変memory、未宣言exportを認めない。生成後にcanonical ABI validatorとtarget IR parserを通し、resource limit超過は成功へ格上げしない。

## Digest binding

compiler成果物は次を同時に束縛する。

- APLOT source digest
- fragment schedule digest
- K7 certificate digest
- generated runtime manifest digest
- Wasm module digest
- target IR digest
- ABI digest
- compiler manifest digest
- QSM capsule digest
- observer registry digest

compiler manifestにはservice alias、epoch、policy hash、active frame capacity、TTL、fragment bytes、event count、application retry countを含める。いずれかのartifactを差し替えた場合、同じbindingとして受理してはならない。

## 非主張

- P1 resource equivalence: `NOT_VERIFIED`
- source-target refinement: `NOT_VERIFIED`
- robust adversarial equivalence: `NOT_VERIFIED`
- real BLE controller equivalence: `NOT_VERIFIED`
- radio timing equivalence: `NOT_VERIFIED`
- hardware status: `NOT_VERIFIED`
- 文献・特許上の優先権またはworld-first: 主張しない

このIssueの成果物はcandidate compiler mechanismであり、実radio実験やhardware検証の結果ではない。三系統engine差分評価はIssue #179、adversarial refinement bundleはIssue #180で扱う。
