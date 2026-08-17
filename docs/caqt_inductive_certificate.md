# CAQT inductive reachability certificate

Status: K7-03 version 1

## 1. 目的

CAQT inductive extensionは、synthesizerの「全探索した」という自己申告ではなく、有限product
state invariantを独立checkerが再計算できるようにする。base CAQTのmagic `CAQT`とは別に、
inductive artifactはmagic `CAQI`を使う。counterexample artifactやbase certificateを
inductive proofとして解釈しない。

## 2. Artifact structure

`CAQI-v1`は次をcanonical orderで保持する。

- version
- base CAQTの全domain hash
- domain-separated base-certificate digest
- canonical base CAQT bytes
- independently expectedなinitial product-state pairs
- exact reachable inductive invariant
- invariant pairと全environment inputに対するclosure record

Closure recordはpair index、input、再計算対象の左右successor、次pair indexを持つ。左右が
同じstateへ収束した場合だけ次pair indexを省略できる。

## 3. Independent inputs

Checker callerは`ExpectedInductiveContract`として次を独立に渡す。

- base CAQT version
- spec、plant、quotient、observer、utility、fault、transducer、checker contract hash
- state boundとcost budget
- initial product-state pair set

Certificate内のhashやinitial pairだけを信頼しない。base verifierはobserver divergence、
relation closure、utility、recoverable fault、state reachability、costを再計算する。

## 4. Acceptance judgment

`VALID`には次がすべて必要である。

1. CAQI encodingがcanonicalでtrailing dataを持たない。
2. embedded base CAQTが独立contractに対して`VALID`である。
3. bound hashとbase digestが一致する。
4. initial pairが独立入力と完全一致し、invariantへ含まれる。
5. invariant pairがbase CAQT relationへ含まれる。
6. 各pair・各inputのsuccessorをbase transition tableから再計算できる。
7. 非対角successorがinvariant内の正しいpair indexを指す。
8. initial pairからclosure edgeをたどってinvariant全体へ到達できる。

このため、state削除、edge削除、record reorder、hash差替え、trailing data、未到達pairの
追加を受理しない。reachable unsafe pairを隠した場合、再計算successorとclosure witnessが
一致せず`INVALID`になる。

## 5. Resource outcomes

Decoderは総bytes、embedded base bytes、product-state records、closure recordsをallocation前に
制限する。上限超過は`RESOURCE_BOUND`であり`VALID`ではない。parse errorは`INVALID`、versionや
magic不一致は`INCOMPATIBLE`である。

Valid reportはcertificate bytes、initial pair数、product state数、closure record数、
deterministic check work unitsを返す。`std` buildのtimed wrapperはwall-clock check durationも
別fieldで返す。wall-clock値をsecurity semanticsやdeterministic resource proofへ混入しない。

## 6. Trust boundary

Core decode・checkは`alloc`だけを使い、solver、synthesizer、filesystem、network、private
biosignal型へ依存しない。Builderはcanonical witnessを生成する便宜APIであり、builder出力は
checkerを通るまで証明ではない。

## 7. Non-claims

このartifactはunbounded machine、arbitrary runtime、hardware、timing side channelを証明しない。
また、優先権やworld-firstを主張しない。
