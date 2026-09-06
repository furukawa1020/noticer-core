# QuotientForge Canonical Action Quotient

## 目的

K7-07aはprivate-history stateをauthorized action semanticsだけで分割するcanonical quotient relationを固定する。observer、utility、fault保存やperformanceは後続Issueで別に検査し、この段階のPASSへ混ぜない。

## action-semantics signature

各stateのaction semanticsは、公開observation digestとauthorized action digestの組をsortした非空集合として表す。重複atom、非canonical順、digest不一致は拒否する。signatureはprivate-history labelやstate indexを含めず、canonical JSONのSHA-256である。

## relation contract

入力relationはordered pair集合であり、次を順に検査する。

1. 全edgeが既知source indexだけを参照する。
2. relation edgeが異なるaction-semantics signatureを結ばない。
3. 全stateにreflexive edgeがある。
4. 全edgeにreverse edgeがある。
5. 全2-step pathにtransitive edgeがある。
6. 同じsignatureを持つ全state pairがrelationに含まれる。

このためrelationはaction-semantics equalityと完全一致する。異 semantics の誤mergeだけでなく、同 semantics の恣意的な過剰分割もfail closedする。

## canonical class

classはaction-semantics SHA-256の辞書順で並べ、0から連続するclass IDを付ける。公開artifactに含むのはproblem digest、state/class数、relation pair数、各classのsemantics digestとmember countだけである。

source indexからclass IDへのmapはprocess内の`QuotientPartition`にだけ保持し、serializeしない。private-history labelはsignature、artifact、artifact digestのいずれにも含めない。problem digestにはK7-06bでprivate labelをequivalence-class IDへ正規化したfingerprintを使う。

## 検証範囲

property smoke testはstate入力順とprivate label renameで同一artifactになること、異 semantics merge、非反射・非対称・非推移relation、同 semantics split、duplicate index/edgeを拒否することを確認する。

このbounded structural checkをobserver trace保存、utility/fault保存、探索削減、無制限traceの証明とは呼ばない。
