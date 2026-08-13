# APLOT BLE Transport Protocol v1

## Wire layout

fragmentは常に20 bytesである。

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | marker 0x41 |
| 1 | 3 | public frame ID |
| 4 | 1 | fragment index |
| 5 | 15 | fragment payload |

total countはprofileで20に固定され、wire上へ可変値として送らない。indices 0..15はdata、
16..19はparityである。各ATv2 envelopeの末尾へ4個のzero byteを加え、240 bytesを
15-byte単位へ分割する。

## Sender contract

- Write Without Responseを使う。
- 公開start tickから固定cadenceで20回だけwriteを試みる。
- write failure後も残りの公開slotを維持する。
- failed fragmentをapplicationから再送しない。
- token内容に応じてconnect、disconnect、MTU negotiation、cadenceを変えない。
- connection-level回復が必要な製品では、公開epoch境界に固定した別profileとして定義する。

## Receiver contract

- parserは任意lengthと任意byte列でpanicしない。
- fixed-capacity slotだけを使う。
- duplicateが同一payloadなら状態を変えない。
- conflicting duplicateではframe全体を破棄する。
- TTL超過ではframeを破棄し、部分tokenを保存しない。
- 一group二個以上の欠損は回復不能としてtimeoutへ閉じる。
- full envelope以外をverifierへ渡さない。

## Observer model

Network Observerは接続時刻、write回数、20 bytes全部、frame ID、index、順序、loss、
切断を観測できる。暗号化済みpayloadも観測面に含むため、counterfactual testはmetadataだけ
ではなくin-memory wire bytesも比較する。永続artifactにはtoken fragment自体を保存しない。

## 既知制約

- 24-bit frame IDにはbirthday collision riskがあるため、長期識別子として使用しない。
- XOR parityはByzantine訂正を行わない。改ざんはATv2 verifierが拒否する。
- BLE controllerやOS schedulingの実測分布はTier Bで未検証である。
- advertising、pairing、MTU negotiationを含む完全なradio trace同値性は本profileの主張外である。
