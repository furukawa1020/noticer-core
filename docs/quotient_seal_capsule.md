# QuotientSeal Module Capsule v1

## 1. 目的

QuotientSeal Module Capsule（QSM、拡張子`.qseal`）は、source certificate、
WASM、公開ABI、observer集合、relation certificate、robustness certificate、
resource certificateを、独立checkerが再検証できる単一のcanonical containerへ束ねる。

QSMはcompilerの署名や自己申告を正しさの根拠にしない。compilerとengineのmanifestは
再現性を調査するためのevidenceに限定し、accept判定へ権限を与えない。

本仕様はsecure compilationを構成する候補実装の検証境界を定めるものであり、
優先権、新規性、world-first、hardware実証を主張しない。

## 2. Trust boundary

独立checkerが信頼するものは、checker自身、固定されたQSM v1 decoder、公開された
resource上限、semantic recomputation backendだけである。次は信頼しない。

- capsuleを生成したcompiler
- compiler/engine manifestの内容
- capsule内に保存された「検証成功」という自己申告
- sectionの順序、長さ、digestに関するproducerの解釈
- resource上限を拡張しようとするcapsule内の値

semantic backendへcompiler manifestは渡さない。manifestを書き換えても不正な意味保存を
正当化できないAPI境界にする。

## 3. Canonical wire format

QSM v1は8-byte magic `QSEALCAP`、version、section count、reserved field、宣言された
全長を持つ。section countは9で固定し、reserved fieldは0だけを許可する。各sectionは
type、reserved field、payload length、domain-separated SHA-256 digest、payloadから成る。

section順序は次で固定する。

| 順序 | Section | 内容 |
|---:|---|---|
| 1 | `resource_bounds` | producerが要求する有限上限 |
| 2 | `source_certificate` | canonical source/inductive certificate |
| 3 | `wasm_module` | 検証対象WASM bytes |
| 4 | `abi_manifest` | QuotientSeal ABI v1 |
| 5 | `observer_registry` | O0からO6までの固定observer集合 |
| 6 | `relation_certificate` | source-target relation evidence |
| 7 | `robust_certificate` | adversarial context product evidence |
| 8 | `resource_certificate` | strictまたはnormalized resource evidence |
| 9 | `compiler_manifest` | 非信頼の再現性metadata |

同じsource、WASM、各certificate、設定からはbyte-identicalなcapsuleを生成する。
未知version、未知section、順序違反、非zero reserved、空section、長さ不一致、digest不一致、
末尾byte、hard limit超過をcanonical inputとして受理しない。

## 4. Domain separation

section digestはsection種別ごとに異なる固定domainで計算する。同じpayloadを別sectionへ
移してもdigestを再利用できない。capsule全体を一つだけhashする設計にはせず、decoderが
長さと順序を確定した後に各payloadを再hashする。

一つのbitでもsource、WASM、ABI、observer、relation、robustness、resource、manifestの
いずれかが変化した場合、元のdigestを持つcapsuleは`INVALID`となる。

## 5. Independent semantic recomputation

format検証を通過しただけでは`VALID`にしない。checkerは少なくとも次を再計算する。

1. WASMをbounded parserでcanonical target IRへlowerする。
2. WASM export/import/memory surfaceをABI v1 manifestと照合する。
3. source certificateとrelation certificateをcanonical decoderで再構成する。
4. target digest、relation digest、source binding、inductive bindingを照合する。
5. O0からO6の全observer profileについてproduct判定を再実行する。
6. 全context familyと少なくとも1組のprivate pairを評価したことを確認する。
7. strict resource equivalence、または上限内のnormalizationを再検証する。

別processから同じ公開APIを呼び、同一bytesを検証できることを試験条件にする。

## 6. Verdict taxonomy

| Verdict | 意味 |
|---|---|
| `VALID` | format、binding、semantic relation、context、resourceの再計算が全て成功 |
| `COUNTEREXAMPLE` | boundedな具体的反例を再計算で得た |
| `INVALID` | malformed、非canonical、digest/binding不一致、矛盾したevidence |
| `INCONCLUSIVE` | backend不在、parser consensus不成立、resource上限到達などで決定不能 |

`INCONCLUSIVE`を`VALID`へ格上げしない。timeout、fuel枯渇、未対応命令、backend protocol
failureも成功として扱わない。

## 7. Resource contract

checkerはbuild時に固定したhard boundsを持つ。capsule内`resource_bounds`は、その範囲内で
producerが要求するより小さい上限だけを宣言できる。宣言値がhard boundsを一つでも超える
capsuleは実行前に拒否する。

長さはallocate前に検査し、加算・変換はoverflowを拒否する。parser work、semantic step、
context pair、normalization overheadも有限値として扱う。resource limit到達は証明成功ではない。

## 8. Reproducibility and artifacts

再現性の最低条件は次である。

- 同一入力から得た`.qseal`がbyte-identicalである。
- checkerを別processで実行して同じverdictを得る。
- 全sectionへのone-bit mutationが受理されない。
- unknown version、trailing bytes、oversize lengthをfail closedで拒否する。
- compiler manifestだけを変更してsemantic authorizationを得られない。

generated `.qseal`、一時WASM、checker outputは実験artifactでありGitへcommitしない。
固定契約は`configs/quotient_seal/capsule_v1.yaml`と
`schemas/quotient_seal_capsule_v1.schema.json`に保存する。

## 9. Non-claims

- 任意の無限実行に対する完全なprogram equivalenceは主張しない。
- checker外のOS、runtime、hardware side channelを検証済みとはしない。
- compiler manifestからcompiler correctnessを導かない。
- 実hardwareでの成立は`NOT_VERIFIED`である。
- 文献・特許調査が完了するまで優先権や世界初を断定しない。
