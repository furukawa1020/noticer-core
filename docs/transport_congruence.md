# Transport Congruence Premise

## 1. Status

K6開始時点のtask記述では`docs/transport_congruence.md`を既存前提として参照していたが、実repository treeには存在しなかった。本書はその欠落を隠さず、現在の実装crateに基づいてtransport congruence前提を明示する。

## 2. Actual implementation boundary

現在のtransport関連責務は単一crateではなく次へ分かれている。

- `noticer-aetp`: action-equivalent trace semantics
- `noticer-trace-shaper`: AETS logical-slot release shaping
- `noticer-token`: ATv2 token/frame内容
- `noticer-protocol`: wire protocol/frame planning
- `noticer-transport-core`: APLOT fragmentation、reassembly、public loss model
- `noticer-transport-sim`: transport simulationと`PublicLossTape`の所有
- `noticer-ble-host`: host側BLE境界
- `noticer-menfugu-core`: authorized action execution境界

QF adapterはこれらを統合型へ複製せず、既存crateを直接参照する。

## 3. Congruence relation

2つのprivate historiesが同じaction semanticsを持つとき、transport congruenceに必要な条件を次とする。

1. logical release slot列がobserverごとに等しい
2. ATv2 frame countとobserver-visible size classが等しい
3. APLOT fragmentation/reassembly decisionが同じpublic contextと`PublicLossTape`だけで決まる
4. retry/reconnectがprivate evidenceではなくpublic lossへだけ依存する
5. recoverable failureのobserver-visible normalizationが等しい
6. Menfugu action windowとauthorized actionが同じaction semanticsへ対応する

K6 checkerが直接検査するのはfinite logical modelである。BLE radio timingとOS schedulingはこのrelationへ含めない。

## 4. Bounded-loss premise

APLOT valid判定はbounded public lossを前提とする。

- loss eventは左右走へ共通のpublic inputとして与える
- retry budgetとreconnect decisionはpublic fieldである
- boundを超えたlossは`INCONCLUSIVE`または明示failureであり、private-dependent fallbackへ移らない
- packet lossをsecretとして扱わない

この前提なしにhandwritten APLOTをunbounded traceでvalidと主張してはならない。

## 5. Evidence required for stronger claims

logical congruenceを実transport claimへ拡張するには次が別途必要である。

- ATv2 frame plannerとgenerated outputのbyte-level vector
- APLOT fragment count、retry、reconnectのpublic-only trace
- BLE host/firmware間のloss/reorder実測
- Menfugu action window enforcement log
- timing/size observerに対するattack evaluation

これらがない段階では、保証をfinite modelとsoftware adapterに限定する。
