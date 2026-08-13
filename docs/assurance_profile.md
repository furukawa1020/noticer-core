# Assurance Profile

## 位置づけ

`AssuranceProfile` は、入力がどの程度信頼できるかを単一の強度へ潰さず、互いに独立した5軸で表現する。

この型は Action-Equivalent Provenance Attestation (AEPA) の保証境界をコードへ固定するためのものであり、センサー真正性、完全な端末完全性、または実行時パイプラインの真正性を単独で証明するものではない。

## 5つの保証軸

| 軸 | 保守的な初期値 | より強い値の意味 |
|---|---|---|
| Source | `Synthetic` / `Replay` / `PairedCommercialSensor` | センサー自身が署名した入力 |
| Collector Key | `Software` | TEEまたはStrongBoxで保護された収集鍵 |
| Boot State | `Unknown` / `Reported` | 検証済みかつロックされた起動状態 |
| Pipeline | `SelfDeclared` | 静的manifestへの結合、または実行証明 |
| Freshness | `None` / `LocalMonotonic` | verifier challengeへの結合 |

現在のTier A実装は、検証根拠なしに右側の強い値を生成しない。強い値は将来のattestation verifierが根拠を検証した後にのみ発行できるよう、列挙子を公開APIから隠している。

## Product Order

2つのprofile `a` と `b` について、`a` が `b` 以上に強いとは、全軸で `a` が `b` 以上である場合に限る。

~~~text
a >= b
iff
a.source        >= b.source
and a.collector >= b.collector
and a.boot      >= b.boot
and a.pipeline  >= b.pipeline
and a.freshness >= b.freshness
~~~

したがって、ある軸で強く別の軸で弱いprofileは比較不能である。たとえば、fresh challengeを持つsoftware keyと、freshnessを持たないhardware-backed keyのどちらかを一律に「上」と扱ってはならない。

`meet` は各軸の弱い方を、`join` は各軸の強い方を選ぶ。これらはprofileの比較や試験用であり、`join`によって実世界の証拠を合成できることを意味しない。証拠のappraisalを経ずに`join`の結果をproduction leaseへ利用してはならない。

## 格上げ防止

- Polar等の通常のpaired commercial sensor adapterが主張できるSource上限は`PairedCommercialSensor`である。
- software attesterが主張できるCollector Key上限は`Software`である。
- 未検証のboot情報は`Reported`を超えない。
- self-declared pipeline hashは`SelfDeclared`を超えない。
- ローカル単調時刻はverifier challenge freshnessではない。
- productionが既定モードであり、未証明経路は明示的な`LAB_UNATTESTED`でのみ選択する。

強い内部rankを直接構築しようとするcompile-fail doctestと、全profile組合せに対する順序則のunit testでこの境界を固定する。

## 安定digest

profileは5軸を順序固定した1 byteずつへ符号化し、domain separator付きSHA-256でdigest化する。このdigestはNPL1 lease、監査artifact、およびpolicy bindingで同じprofileを参照するために使う。

digestは保証そのものではない。検証済みprovenance evidenceからappraiserがprofileを導出し、そのprofile digestをleaseへ結合して初めて意味を持つ。

## Policy

`ProvenanceAppraisalPolicy` は少なくとも次を固定する。

- 許可するcollector identity
- 許可するpipeline measurement
- 発行可能なleaseの最大slot数
- 受理に必要な最小Assurance Profile

空のcollector集合、空のpipeline集合、または0 slotのleaseは拒否する。profile比較は各軸を個別に検査し、総合スコアや平均値へ変換しない。

## 非主張

この段階では次を主張しない。

- Polar Verity Senseサンプルのsensor-native signature
- hardware-backed collector key
- Android boot stateの暗号学的検証
- pipelineのruntime proof of execution
- remote verifier challenge freshness
- AEPA全体の成立

これらは後続Issueで証拠形式、appraisal、lease、production guardを接続し、利用可能な実機Tierごとに検証する。
