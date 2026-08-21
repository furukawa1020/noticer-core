# AEPA Public Admission Source v1

## 目的

この文書はIssue #188で固定するAEPA public admission sourceとK7 bindingの境界を定義する。対象は`P0 Public Quotient Only`であり、P1 Sealed Admissionは実装しない。

source machineは、署名、service、epoch、policy、pipeline、assurance、expiry、replayを既存K5 trusted pathが検証した後に得られる公開symbolだけを扱う。`VALIDATED_ADMISSION`はlease bytesやprivate appraisalを意味せず、それらをsource machineへ渡す入口でもない。

## 公開machine

状態は`WAITING`、`ADMITTED`、`COVER_REQUIRED`、`FAULTED`の4種とする。入力はpublic tick、validated admission、replay、expired、downgrade、wrong binding、reset、handoff、faultの9種である。出力はcover、admit once、reject、faultの4種である。

全状態と全入力のtransitionをtotalに定義する。`WAITING`での最初のvalidated admissionだけが`ADMIT_ONCE`を出力する。同一session内の重複admission、replay、expiry、downgrade、wrong bindingは許可へ昇格せずrejectまたはcoverへ閉じる。resetとhandoffはprivate stateを持ち越さず`WAITING`へ戻す。faultは`FAULTED`へ遷移する。

## Binding

canonical sourceは次の公開値だけを束縛する。

- wire service aliasとpairwise service alias
- public epochとpolicy hash
- NPL1 profile/versionとlease verifier key ID
- pipeline measurement hashとassurance profile digest
- ATv2 issuer key ID
- public admission window
- source、K7 certificate、generated runtimeのdigest

source artifactは同じ入力からbyte-identicalに再計算できなければならない。Noticer QSM registryのAEPA entryは同じservice、epoch、policy、source、certificate、runtime digestを持ち、deployment profileはP0でなければならない。

## 消去境界

次の値はcanonical source、manifest、certificate binding artifactへ含めない。

- raw PPG、ACC、biosignal history
- private feature、baseline、appraisal
- EvidencePermitとprovenance lease bytes
- lease nonce
- collector session public key hash
- Android attestation certificate chain
- private resource trace

この消去はlease validationの代替ではない。runtimeで`VALIDATED_ADMISSION`を生成できるのは既存の署名・binding・lifetime・replay検証を通過したtrusted pathだけである。

## P1と非主張

P1 Sealed Admissionはprivate resource trace equalityの再計算可能な証拠が必要であり、Issue #190まで受理しない。P0 source、synthetic fixture、CI、software differential testだけで実端末、Polar、Android hardware attestation、hardware-backed keyを検証済みとはしない。hardware statusは`NOT_VERIFIED`である。

これはcandidate integration contractであり、文献・特許上の優先権またはworld-firstを主張しない。
