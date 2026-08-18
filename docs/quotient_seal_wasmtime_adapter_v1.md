# QuotientSeal Wasmtime adapter v1

## 位置づけ

このadapterは、K8-12aで凍結したcross-engine実行契約へWasmtimeを接続する実行境界である。独立したsecurity primitiveや優先権を主張せず、QuotientSealのcandidate moduleを別engineで観測するための実験実装として扱う。

## 凍結するengine条件

- Wasmtime crateは`34.0.2`へexact pinする。
- Cargo featureは`cranelift`、`runtime`、`std`だけを有効化する。
- Cranelift最適化levelは`none`とする。
- fuel消費とepoch interruptionを有効化する。
- NaN canonicalizationは無効化し、値を文字列へ丸めない。
- float operator/localはABI通過後のengine-feature gateで拒否し、SIMD、relaxed SIMD、memory64、multi-memory、tail-callはWasmtime configで無効化する。
- engine identityはadapter profile、engine version、feature/configuration、enclosing process SHA-256を含む。

## resource境界

fuel、linear memory、host-call回数はadapter内で決定的に制限する。epoch interruptionは有効化するが、epochを進める責務と`timeout_ms`のwall-clock監視はouter orchestratorへ残す。adapter単体がOS scheduler依存のthreadを起動すると同一入力のartifact再現性を壊すためである。

outer orchestratorが期限切れを通知した場合は`TIMED_OUT / UNRESOLVED`とする。fuel、memory、host-call枯渇も成功へ正規化せず`RESOURCE_EXHAUSTED / UNRESOLVED`とする。

## observable境界

採取対象はoutput、public state、trap、return、host import、reset、handoffである。host tapeは順序、件数、outcomeを完全一致させ、余剰・不足・順序違反を`UNRESOLVED`として保存する。

trapはWasmtimeのtyped `Trap`を分類し、engine codeを残す。NaNは共通契約の`F32_BITS` / `F64_BITS`でbit-exactに表現する。ただしP0 ABIでfloat instructionが許可されることを意味しない。

## 主張しないこと

- Wasmtime JITのnative instruction trace equality: `NOT_VERIFIED`
- wasmiとWasmtimeの内部instruction sequence equality: `NOT_VERIFIED`
- wall-clock timeoutのadapter単体再現性: `NOT_VERIFIED`
- 実機、組込み機器、TEE上での挙動: `NOT_VERIFIED`

instruction traceの規範はreference interpreterだけに置く。engine間比較は凍結したobservable artifactに限定する。
