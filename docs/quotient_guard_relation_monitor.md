# QuotientGuard online relation monitor

monitorはshadow executorの公開outcomeだけを入力とし、個別private stateを受け取らない。

- equivalent prefixを連続slotでのみ受理する。
- 最初のdivergence slot、分類、prefix長、比較shadow数だけをwitness化する。
- divergence witnessはstickyで、後続入力によって上書きできない。
- slot skip/replay、shadow不足、resource exhaustionはfail-closed sinkへ送る。
- resource exhaustionはsecurity successとして扱わない。

このmonitorのwitnessはbounded runtime evidenceであり、K9 certificateや普遍的security proofの代替ではない。
