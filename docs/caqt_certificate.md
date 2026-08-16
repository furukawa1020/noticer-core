# CAQT Certificate and Independent Checker

## 1. 位置づけ

CAQT（Certificate for Action-Quotient Transducers）は、AQRS synthesis結果を独立checkerで再検査するためのversioned certificate形式である。

CAQTはsolverの成功応答、solver内部model、最適性claimを証明として扱わない。checkerはcertificateへ収録された有限遷移系を自分で走査し、trusted inputとして別経路から渡された`ExpectedContract`と照合する。

この文書と実装はproposed security notionを支える候補certificate境界であり、既存研究に対する優先性や世界初を主張しない。

## 2. Trusted boundary

checkerが外部から信頼して受け取る値は次である。

- 対応format version
- spec、plant、quotient、observer、utility、fault、transducerのexpected hash
- checker contract hash
- state bound
- component-wise cost budget
- parser resource limit

certificate内部の同名hashは自己申告値にすぎない。受理には、checker再計算値、certificate自己申告値、外部expected値の三者一致が必要である。

solver library、synthesis engine、private acquisition type、OS I/Oはchecker coreへ含めない。

## 3. Canonical wire format

CAQT v1はlittle-endianのlength-prefixed binary形式である。順序は次で固定する。

1. magic `CAQT`とversion
2. 8個のdomain-separated SHA-256 hash
3. state/input/observer数、state bound、claimed cost
4. observer、output、transition、relationのrecord数
5. ID昇順のobserver table
6. ID昇順のoutput table
7. `(state, input)`辞書順かつ全域なtransition table
8. `(left, right)`辞書順のaction-equivalence relation

relation pairは`left < right`のunordered pairとしてcanonical化する。record reorder、duplicate transition、missing transition、reserved action ID、未参照output、silent outputへのdata付与、trailing bytesは拒否する。

parserはallocation前にcertificate byte数、record数、payload長、action数を検査する。

## 4. Domain hash

各hashは`CAQT-DOMAIN` prefixとdomain名を含むSHA-256 preimageから計算する。

- `plant`: state/input dimensionと遷移先
- `quotient`: action-equivalence relation witness
- `observer`: observer projection定義
- `utility`: authorized action集合とrequired action
- `fault`: recoverable fault action
- `transducer`: output内容とrelease transition
- `spec`: plant/quotient/observer/utility/fault hashの結合
- `checker_contract`: v1の検査規則とcost定義

transition、output、relation witness、observer、utility、faultの改変は対応domain hashを変える。攻撃者がcertificate内hashも更新した場合は、外部expected hashとの不一致で拒否する。

## 5. Independent recomputation

checkerは次を再計算する。

- 全state/inputに対するtransition totality
- relation pairごとの全observer observation equality
- transition後state pairのrelation closure
- unauthorized action、duplicate action、required action exactly-once
- recoverable fault action exactly-once
- state bound
- state 0からの全state reachability
- 全outputが少なくとも1 transitionから参照されること
- state数、emitting transition数、payload byte数、action emission数からなるcost

observer observationはrelease presence、payload、action列のうちobserverが見える軸だけから再計算する。certificateがobserver view digestを自己申告する方式は採らない。

## 6. Verdict

APIは次の3値を区別する。

- `VALID`: canonical、hash、property、bound、costの全検査に成功
- `INVALID`: 改変、非canonical、property違反、resource-safe parse失敗
- `INCOMPATIBLE`: magic、version、checker contractがこのcheckerと非互換

`INVALID`と`INCOMPATIBLE`を合成失敗や充足不能判定へ読み替えてはならない。

## 7. no_std境界

次でcoreをbuildできなければならない。

```bash
cargo check -p quotient-forge-caqt --no-default-features
```

この構成は`core`と`alloc`だけを使用し、K6-03 IR compatibility markerも外す。default featureではmarkerを有効にするが、certificate検証アルゴリズム自体はIR crateへ依存しない。

## 8. 非保証事項

CAQT v1は次を保証しない。

- frontend DSLからfinite modelへのloweringの正しさ
- 無限traceの性質
- expected hashを配布する経路の真正性
- SHA-256実装に対するside-channel耐性
- solverの最適性
- hardware timing、BLE radio、OS schedulingの実測挙動
- certificate外のobserverまたはside channel

CAQTはfinite bounded modelの小さな独立再検査器であり、完全なproof assistantまたはhardware attestationではない。
