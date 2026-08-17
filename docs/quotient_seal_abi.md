# QuotientSeal capability-separated WASM ABI v1

Status: FROZEN v1

Machine-readable contract: configs/quotient_seal/abi_v1.yaml

Schema: schemas/quotient_seal_abi_v1.schema.json

## 目的

K8-02はprivate ingressとadversarial public contextを、Rust object capability、
public wire、実WASM import/export surfaceの三層で分離する。manifestが宣言した
surfaceは信用せず、validatorがbinary sectionから型とsymbolを再計算する。

## Capability境界

TCBはprovisioning時にTrustedIngressとPublicContextを分割し、前者を保持して後者だけを
contextへ渡す。PublicContextから可能な操作はtick、reset、handoff、statusだけである。
TrustedIngressはClone、PublicWireEncode、PublicContextへの変換を実装しない。

別instanceをprovisionしても既存のprotected instanceに対するprivate capabilityは得られない。
Rustの型だけで呼出主体の身元を認証する主張は行わず、capability配布をTCBの責務とする。

## Public wire

public requestはQSAB magic、version 1、固定24 byte、little-endianである。tickはnonzero
service alias、u64 public slot、NONE・TIMEOUT・RECONNECT・LOSSのpublic faultを持つ。
resetとstatusは未使用fieldをzeroにし、handoffはslotだけを持つ。

長さ違反、unknown method、unknown fault、nonzero reserved、method固有field違反はrejectする。
private bytes、biosignal、baseline、private historyをwire上で表現するtagは存在しない。

## WASM surface

許可するhost importは次の3つだけである。

- qseal.emit_frame
- qseal.emit_action
- qseal.public_failure

許可するpublic exportは次の4つだけである。

- qseal.public.tick
- qseal.public.reset
- qseal.public.handoff
- qseal.public.status

qseal.private.ingestはhost-side capability名であり、WASM importにもexportにもならない。
private functionがmodule内部に存在してもexportされない限りpublic contextは名前解決できない。
extra symbol、wrong signature、private export、wrong ABI hashはINVALIDである。parser上限超過は
RESOURCE_BOUNDでありVALIDへ縮退しない。

## Profile

P0 Public Quotient Onlyはprivate admissionなしでpublic quotientだけを実行する。

P1 Sealed AdmissionはTCBが保持するTrustedIngressで得たopaque admissionを使うが、public
WASM surfaceはP0と同一である。profile差を理由にprivate APIを追加しない。

## 非主張

- K8-03のrestricted WASM instruction parserを先取りしない
- K8-04のsmall-step実行意味論を実装しない
- K8-05のsource-target relationやRAQTR preservationを証明しない
- malicious runtime、OS compromise、linear memory直読、microarchitectureを保証しない
- 実機・BLE・wearable hardwareはNOT_VERIFIED
