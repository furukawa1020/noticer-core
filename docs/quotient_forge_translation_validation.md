# CAQT cross-target translation validation

## 位置づけ

K7-10は、VALIDなCAQT証明書から生成したruntimeについて、証明書の意味論と
native no_std実装およびwasm32-unknown-unknown実装が一致するかを判定する。
これはdeployment readinessの必要条件であり、実機上の安全性を証明するものではない。

## 信頼境界

参照側はCAQT bytesを再decodeし、全stateと全inputの直積から一段遷移を再構成する。
生成側のtransition tableを参照結果として再利用しない。比較対象は次の通り。

- status
- next state
- output ID
- qf-fixed-le-v1で符号化したoutput bytes
- 全stateのreset、handoff、restore
- quotient、public、faultの範囲外入力
- 不正stateとoffset arithmetic overflow
- 64 stepのbounded sequence

件数不足と余剰観測も不一致である。比較の途中で上限へ到達した場合はVALIDへ縮退せず、
RESOURCE_BOUNDを返す。

## Artifact binding

生成runtimeはCAQT certificate digestとcodegen manifest digestを埋め込む。
検証transcriptはtarget、compiler、compiler version、build commandも記録する。
digest不一致、build metadata欠落、target不一致はfail-closedで扱う。

## 実WASM経路

test jobはwasm32-unknown-unknown targetとNode.js 24を導入する。試験は生成crateを
release cdylibへcompileし、Node.jsのWebAssembly engineで実際にinstantiateする。
生成したno_std sourceをrustcでWASM cdylibへcompileし、host importとprivate、
biosignal、ingestに該当するexportを拒否したうえで、全遷移、
全output byte、lifecycle、invalid probe、bounded sequenceを照合する。

生成transition tableを改変したnegative testは、実WASMを再buildして
next-state mismatchを観測しなければ失敗する。

## 判定

- VALID: 指定された有限意味論とartifact bindingが完全一致した
- MISMATCH: 値、順序、件数、digestのいずれかが一致しない
- INCOMPATIBLE: targetまたはbuild metadataを比較契約へ適合させられない
- RESOURCE_BOUND: 観測件数またはoutput sizeが検証上限を超えた

MISMATCH、INCOMPATIBLE、RESOURCE_BOUNDはいずれもdeployment-readyではない。

## 非主張

- 実機、BLE、wearable hardware上での検証は行っていない
- compiler correctnessやWebAssembly engine correctnessは証明していない
- unbounded trace equivalenceやconstant-time性は証明していない
- candidate new primitiveや世界初性を主張する成果ではない
