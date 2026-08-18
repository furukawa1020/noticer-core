# QuotientSeal WASM binary mutation taxonomy v1

## 目的

K8-11aは、実compilerが出力したWASM byte列をsource generatorから独立に変更するための
決定的editorを固定する。37 operatorをaction、state、context、trap、memory、resource、
bindingの7 familyへ分ける。

この段階ではmutantのkill rateや防御効果を主張しない。実compiler outputに対する全campaignは
`NOT_VERIFIED`であり、未検証の優先性・世界初を示すものではない。

## Binary-level契約

- 入力はWASM magicとversionを含む完成binaryであり、Rust sourceやcode generatorを変更しない。
- core sectionを分解し、変更後のsection sizeをcanonical unsigned LEB128で再構築する。
- code body size、vector count、import・export・global・data sectionをbyte単位で更新する。
- 各mutantへoperator IDを持つcustom witness sectionを追加し、同一seedとoperatorから同一byte列を得る。
- primary editのsection ID、offset、before、after、locusを保存する。
- 必要なcode、call、memory access、data segmentがないoperatorは`NotApplicable`とし、成功へ数えない。

custom witnessはmutantの一意なprovenanceであり、security mutationそのものではない。各mutantは
witnessとは別にprimary editを必ず1件持つ。binding familyの2 operatorはbinding custom sectionを
primary editとして追加する。

## 反証可能性

次のいずれかを満たすeditorは契約違反とする。

- seedを変更する。
- 同じseedとoperatorから異なるbyte列を生成する。
- primary editなしでwitnessだけを追加する。
- 37 operatorの出力が一意でない。
- section lengthが非canonicalになる。
- 不適用operatorをmutant生成成功として返す。

## 次の分割

- #132: module family・compiler configのheld-out分離とartifact runner
- #133: target parser・独立checker接続と三値判定

