# K4: Action-Preserving Link-Oblivious Transport

## 位置づけ

K4では、Action-Equivalent Trace Privacy（AETP）の保護境界をATv2 envelopeの生成後から
BLE断片列、再構成、検証、許可済み物理動作まで拡張する。この輸送方式を
Action-Preserving Link-Oblivious Transport（APLOT）と呼ぶ。

APLOTは candidate transport mechanism であり、単独の暗号方式でも、一般的な匿名通信方式でも
ない。文献上の新規性は別途監査し、world-firstとは断定しない。

## セキュリティ命題

同一の公開plan、公開frame identity、公開loss tape、公開execution slotを持つ二つのprivate
biosignal history H0、H1が同じ許可済みaction semanticsへ写像されるとき、外部観測者が得る
次のtraceを一致させる。

1. 接続policyと送信開始slot
2. 20個のfragment byte列
3. fragment index、順序、長さ、送信cadence
4. 公開loss tapeに基づくdelivery結果
5. application retryが存在しないこと
6. 再構成完了またはtimeoutの公開時点
7. 許可済みactionに対応する公開execution slot

秘密historyが異なるだけで再送、接続、timeout、error detail、pump時間を変えてはならない。

## Trusted Computing Base

TCBに含めるもの:

- K1 EvidencePermitからallowed semanticsを得る既存release境界
- K2 AETP shaperとK3 ATv2 issuer
- noticer-transport-core
- noticer-verifier-core
- noticer-menfugu-core
- firmwareのreassembler、clock、replay store、pump output

TCBに含めないもの:

- BLEリンクそのもの
- Network Observer
- host OSのUI
- artifact収集先
- private biosignalを保持する上流処理

## 固定profile

| 要素 | 値 |
|---|---:|
| ATv2 envelope | 236 bytes |
| zero padding | 4 bytes |
| transport payload | 240 bytes |
| fragment | 20 bytes |
| header | 5 bytes |
| fragment payload | 15 bytes |
| data fragments | 16 |
| parity fragments | 4 |
| total | 20 |

frame IDはtransport ID keyを用いたHMAC-SHA256の先頭24 bitである。HMAC入力はdomain
separator、pairwise service alias、public epoch、public bucket、sequenceだけであり、private
evidence、秘密時刻、token plaintextを含めない。24-bit IDは秘密性を与えず、bounded
reassembler内の短期相関子としてだけ使う。衝突は検証失敗へ閉じ、物理動作へ昇格させない。

## FEC

data indexは0から15、parity indexは16から19である。parity group gは
g、g+4、g+8、g+12のXORとする。各groupにつき一つのdata欠損を回復できる。
FECは認証ではない。改ざん検出の最終境界はATv2 AEADと署名である。

## フェイルクローズ規則

- 20-byte以外、marker不正、index不正を拒否する。
- 同一frame/indexで異なるpayloadを受けた場合、そのframe stateを破棄する。
- active frame数とTTLを固定し、heapを無制限に増やさない。
- 236 bytesが完全に回復し、4-byte paddingがゼロであるまでverifierを呼ばない。
- cover、invalid、expired、revoked、replay、policy mismatchではpumpを動かさない。
- MenfuguInflateSoft以外のactionを拒否する。
- pump duration、cooldown、execution slotは公開設定だけで決める。
- application-level retryを実装しない。

## 反証条件

次のいずれかを観測した場合、K4のAETP拡張主張を棄却または修正する。

- action-equivalent pairで20 fragmentのbyte列または時刻が異なる。
- loss tapeが同じなのに再構成またはexecution traceが異なる。
- incomplete frameでverifierが呼ばれる。
- invalid/replay tokenでpumpが一度でも有効になる。
- private fieldがframe ID、retry、connection policy、artifactへ流入する。
- 実機未試験をTier B verifiedとして報告する。
