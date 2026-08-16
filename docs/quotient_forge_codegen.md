# QuotientForge Certificate-Linked no_std Code Generation

## 1. 目的

`quotient-forge-codegen`は、K6-05 CAQT checkerが`VALID`と判定したfinite transducerから、heapを使わない`no_std` Rust runtimeを生成する。

generatorはcertificate検証前にtarget directoryを作らない。`INVALID`または`INCOMPATIBLE` certificateからはartifactを1 byteも出力しない。

## 2. 入力境界

generator入力は次に限定する。

- CAQT certificate bytes
- 独立経路から得た`ExpectedContract`
- certificate parser resource limit
- public codegen config
- 新規target path

codegen configはquotient/public/fault input軸数を持つ。3軸のchecked productがcertificate input countと一致しなければ拒否する。

private biosignal、private history、sensor sample、uncertified adapterはcodegen入力に含めない。

## 3. Generated runtime API

生成される`step` signatureは次の3入力だけを受ける。

```rust
pub fn step(
    &mut self,
    quotient: QuotientInput,
    public: PublicInput,
    fault: FaultInput,
) -> Result<EncodedOutput, StepError>
```

`PrivateInput`型は生成しない。

runtime state、transition、outputはcompile-time固定長である。`Vec`、`Box`、allocator、mutable static、runtime table injectionを使わない。

## 4. Checked execution

runtimeは次を検査する。

- 各input軸のrange
- quotient/public/faultからlinear input IDへのchecked multiply/add
- current stateとinputからtable indexへのchecked multiply/add
- transition table lookup
- output table lookup
- next state bound

errorは`StepError`で返し、入力由来のpanic経路を持たない。tableはprivate immutable `const`として生成する。

## 5. Stable output encoding

`EncodedOutput`は次の固定layoutをlittle-endianでencodeする。

1. emitted flag 1 byte
2. payload length 2 byte
3. zero-padded payload `MAX_PAYLOAD` byte
4. action count 2 byte
5. zero-padded action ID array `MAX_ACTIONS × 4` byte

encoding IDは`qf-fixed-le-v1`としてmanifestへ記録する。同じoutputのencode結果はbyte-identicalである。

## 6. Generated artifact set

1回の成功で次を同時出力する。

- `Cargo.toml`
- `src/lib.rs`
- `src/vectors.rs`
- `certificate.caqt`
- `codegen-manifest.toml`
- `test-vectors.tsv`

manifestはcertificate digest、8 domain hash、dimension、encoding IDを含む。

targetが既に存在する場合は上書きしない。generated packageは`artifacts/`または一時directoryへ出力し、Gitへcommitしない。

## 7. Behavior equivalence

generatorはcertificateの全transitionをtest vectorへ変換する。各vectorは次を照合する。

- arbitrary source state
- quotient/public/faultへのinput decomposition
- generated `step`後のnext state
- generated outputとcertificate output
- stable output encoding

generator自身のtestは一時directoryへcrateを生成し、`cargo test --offline`を実行する。

## 8. Compile-fail boundary

generated crateはdoctestで次をcompile-failとして固定する。

- 存在しない`PrivateInput`の利用
- private immutable transition tableの変更
- sealed supertraitを持たない外部`CertifiedAdapter`実装

これらはruntime testではなくRust type/privacy systemによる拒否である。

## 9. 非保証事項

codegenは次を保証しない。

- CAQT expected hash配布経路の真正性
- target compiler/toolchain自体の正しさ
- hardware timingまたは電力特性
- generated crateを変更した後のcertificate対応
- Noticer固有transportへのadapter correctness

Noticer adapterとend-to-end integrationはK6-10で実装する。
