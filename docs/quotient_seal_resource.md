# QuotientSeal resource-trace equivalence v1

## 位置づけ

`QUOTIENT_SEAL_RESOURCE_V1`は、K8-05のsource-target relationとK8-06のadversarial context productを通過したtargetについて、action-equivalentなprivate input間のresource traceを比較する追加ゲートである。これはcandidate new primitiveであるQuotientSealの一部であり、優先権や新規性の最終判断を主張しない。

本契約は実機性能の証明ではない。実機上のcache、scheduler、JIT、OS、radio、電力、時間の観測は`NOT_VERIFIED`である。

## strict resource profile

既定モードは`strict`である。各private pairについて、O0 API projectionが同一であっても次の列が1件でも異なれば`ResourceOnly`反例を返す。

| Axis | K8-06 event | 比較対象 |
|---|---|---|
| `opcode` | `Instruction` | opcode label、slot、value、順序 |
| `branch` | `Control` | branch label、slot、value、順序 |
| `memory_address` | `MemoryAccess` | address class、slot、value、順序 |
| `import` | `HostCall` | import label、slot、value、順序 |
| `fuel` | `Resource` | fuel event、slot、value、順序 |
| `memory_pages` | `MemoryGrow` | page growth、slot、value、順序 |

比較は完全一致であり、平均値、分布、許容誤差への緩和は暗黙に行わない。入力caseは`left < right`かつpair昇順でなければ`inconclusive`とする。

## bounded QuotientPad

strict差分がある場合に限り、明示的にnormalization APIを選んだ呼出側は有界な`QuotientPadCandidate`を生成できる。許可する操作は次の5種類だけである。

| Operation | 用途 |
|---|---|
| `public_no_op` | opcode列を揃える公開no-op |
| `bounded_loop` | 宣言上限内でfuelを揃えるloop |
| `branch_fuel` | branch側のfuelを揃える処理 |
| `fixed_scratch` | 固定scratch領域でmemory traceを揃える処理 |
| `failure_return_path` | import failureとreturn pathを揃える処理 |

dummy action、private output、utility変更、deadline違反、無制限paddingは禁止する。候補はcanonical byte列とdomain-separated digestを持ち、instruction、fuel、loop iteration、scratch byteの追加量をartifactへ出す。

## 再検証ゲート

`normalized`はpadding候補を生成しただけでは成立しない。変換後targetを実際に再評価し、次をすべて満たす必要がある。

1. K8-05 relation verdictが`Valid`である。
2. K8-06 context product verdictが`Accept`で、post relation bindingと一致する。
3. O0 API projectionが左右で同一かつ変換前から不変である。
4. utilityが不変である。
5. deadlineが維持される。
6. 6軸のresource traceが完全一致する。

既知の違反は`counterexample`、上限到達、unsupported状態、binding不一致、再検証case欠落は`inconclusive`である。`inconclusive`を成功へ読み替えてはならない。

## verdict

| Verdict | 意味 |
|---|---|
| `strict` | paddingなしで公開面とresource traceが一致した |
| `normalized` | 有界padding後に全再検証ゲートを通過した |
| `counterexample` | 公開面、resource、relation、context、utility、deadlineの既知違反がある |
| `inconclusive` | 上限、unsupported状態、欠落、binding不一致などで判定不能 |

## artifact

`QuotientPadCandidate`と`ResourceCounterexample`は安定したcanonical encodingとSHA-256 digestを持つ。結果交換形式は`schemas/quotient_seal_resource_v1.schema.json`、既定上限は`configs/quotient_seal/resource_trace_v1.yaml`で固定する。hardware statusは実機検証が完了するまで常に`NOT_VERIFIED`とする。
