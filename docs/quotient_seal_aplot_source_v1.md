# APLOT Public Transport Source v1

## 目的

この文書はIssue #177で固定するAction-Preserving Link-Oblivious Transport（APLOT）の公開source artifactとK7 bindingを定義する。

source artifactはP0 QSMへ渡せる公開transport semanticsだけを保持する。236-byte ATv2 envelopeの内容、fragment payload、transport ID key、token plaintext、claim、evidence、baseline、private timestampを含めてはならない。

## 固定shape

APLOT v1は既存`noticer-transport-core`の定数を直接再利用する。

- envelope: 236 bytes
- zero padding後transport payload: 240 bytes
- fragment: 20 bytes
- header: 5 bytes
- fragment payload: 15 bytes
- data fragment: 16個
- parity fragment: 4個
- 合計: 20個

source artifactはpayload byte列を保存せず、各fragmentのordinal、index、scheduled tick、delivered bitだけを保存する。shape定数はcompile-time contractであり、callerが変更できない。

## 公開frame semantics

各frame planは次を持つ。

- pairwise service alias
- public epoch
- public bucket
- sequence
- fragment開始tick
- fragment cadence
- public loss mask
- public reconnect tick列
- deadline tick

artifact全体はactive frame capacityとTTLを持つ。frameはpublic bucket、sequenceの順にcanonicalizeし、reconnect tickは昇順かつ重複なしでなければならない。

20個目のfragment tickはchecked arithmeticで計算する。deadlineは最後のfragment tick以後でなければならない。reconnect tickはframe開始からdeadlineまでの公開区間内に限定する。

## Retry境界

APLOT v1のapplication retry countは常に0である。loss、timeout、reconnect、payload、verification結果を理由に追加fragmentを送信してはならない。

reconnect tickは公開schedule eventであり、再送命令ではない。この区別により、secret-dependent retry stateをsource artifactの表現域から除外する。

## Frame ID境界

実transportの24-bit frame IDはtransport-only keyと公開identityから導出される。source artifactはkeyも実frame ID byteも保持しない。代わりにservice alias、epoch、bucket、sequenceを束縛し、target側ではsymbolic public frame identityとして扱う。

これは24-bit IDの衝突耐性や暗号学的匿名性を証明するものではない。frame ID衝突はfail closedなreassembly境界で別途扱う。

## K7 binding

K7 bindingは次を同時に検証する。

- canonical source digest
- fragment schedule digest
- CAQT certificate digest
- generated runtime manifest digest
- quotient/public/fault input axis
- service alias、epoch、policy hashのregistry binding

certificate、generated runtime、source、registry entryのどれかを差し替えた場合は受理しない。

## 非主張

- private ingress: `FORBIDDEN`
- application retry: `FORBIDDEN`
- real BLE controller equivalence: `NOT_VERIFIED`
- radio timing equivalence: `NOT_VERIFIED`
- hardware status: `NOT_VERIFIED`
- P1 equivalence: `NOT_VERIFIED`
- 文献・特許上の優先権またはworld-first: 主張しない

これはcandidate transport mechanismの公開source契約であり、実radio実験の結果ではない。
