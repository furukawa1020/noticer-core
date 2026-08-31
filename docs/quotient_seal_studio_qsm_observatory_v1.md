# QuotientSeal Studio QSM Observatory v1

## 目的

K8-17bは、`.qseal`のcontainer構造、section digest、source certificateからWASM targetとABI manifestへの結合、capability-separated ABIをbrowser上で監査可能にする。

Observatoryはnative `quotient-seal-capsule` checkerを再実装しない。browser側は構造とdigestを検査する説明面であり、semantic certificate validationのtrust anchorではない。

## Bounded binary parse

実際の`QSEALCAP` binary headerをlittle-endianで読み、次を検査する。

- magic `QSEALCAP`
- format version 1
- section count 9
- reserved field zero
- declared lengthと実byte lengthの一致
- frozen section tagとcanonical order
- section flags zero
- section lengthの上限
- trailing byte不在
- embedded WASM v1 header
- 40-byte ABI manifest header

Studio上限はcapsule 16 MiB、各section 8 MiBである。上限超過は攻撃成功やVALIDではなく`INCONCLUSIVE / RESOURCE_BOUND`とする。unknown version、unknown section、unsupported WASMも`INCONCLUSIVE`とする。

## Digest検証

各sectionはnative実装と同じmaterialをWeb Crypto SHA-256へ入力する。

```text
"CAQT-ARTIFACT\\0"
|| little_endian_u64(domain_length)
|| domain
|| little_endian_u64(payload_length)
|| payload
```

9つのsectionごとにfrozen domainを使用する。declared digestと再計算digestの不一致は`INVALID`であり、該当sectionへdeterministicにfocusする。fixtureのSource Certificate payloadを1 bit変更する操作でこの拒否を再現できる。

すべての構造とdigestが一致しても、browserはrelation、robustness、resource certificateの意味論を検証しないため、判定は`INCONCLUSIVE / NATIVE_SEMANTIC_CHECK_REQUIRED`である。

## ABI capability graph

ABI manifestからversion、deployment profile、ABI hashだけを読む。表示するcapability名はfrozen ABI v1から導出する。

- private: `qseal.private.ingest`
- public: tick、reset、handoff、status
- host imports: emit_frame、emit_action、public_failure

private ingressは破線、`PRIVATE / TCB ONLY`、`NOT IMPORT / NOT EXPORT / NOT WIRE`の文言で示す。色だけへ依存しない。private payload、binding、secret、biosignalはbinary payloadから抽出・表示しない。

## UIと再現fixture

Studioは`.qseal` upload、deterministic fixture、Source Certificate 1-bit tamperを提供する。section mapはbuttonとしてkeyboard操作でき、digest mismatchは記号、文言、色の3要素で示す。desktopではsection/detailを並列表示し、mobileでは1列へ再配置する。

fixtureはcontainer・digest・ABI表示のsmoke evidenceであり、科学的結果やnative security proofではない。hardware statusを検証済みへ変更しない。
