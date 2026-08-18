# QuotientSeal cross-engine実行契約 v1

## 目的

K8-12aは、同じWASM module、public host tape、adversarial context sequence、resource boundを複数engineへ渡すためのengine非依存契約を固定する。ここではWASMを実行せず、wasmi・Wasmtime adapterとdifferential oracleは後続Issueで追加する。

この契約だけからengine間一致やRAQTR成立を主張しない。実engineでの評価状態は`NOT_VERIFIED`である。

## identity binding

`execution_id_sha256`は次の全入力をcanonical JSONへ直列化してSHA-256で束縛する。

- artifact schema version
- module SHA-256とABI SHA-256
- engine名、厳密version、実行binary SHA-256
- adapter contract versionとengine設定全体
- public host tapeとcontext sequence
- fuel、memory、host call、timeout上限

engine version、binary、設定、contextのどれかが変われば別execution IDになる。結果artifact全体には別途`artifact_sha256`を計算できる。

## lossless observable surface

共通観測面はoutput、public state、trap、return、host import、reset、handoffである。float値は表示用数値へ変換せず、`F32_BITS`・`F64_BITS`としてpayload bit列を保存する。したがってNaN payloadと符号bitは失われない。

instruction traceはreference small-step interpreterだけの保証であり、native JIT instruction equalityは契約外である。private memory、JIT code、microarchitectural traceも観測面へ含めない。

## fail-closed三値判定

- `EXECUTED`: normal return、declared trap、明示terminationを観測した
- `REJECTED`: engineがmoduleをinvalidとして拒否した
- `UNRESOLVED`: unsupported feature、timeout、resource exhaustion、engine/tool failureが起きた

trapをtool failureへ潰さず、unsupportedやresource exhaustionを成功またはrejectへ丸めない。verdictとterminationの組合せが不整合ならartifactを拒否する。

## 既存契約の再利用

context sequenceは`quotient-seal-context::ContextCommand`から安定recordへ投影する。host tapeは`quotient-seal-small-step::PublicHostTape`からimport名とoutcomeを失わず投影する。既存の実行意味論を新crateへ複製しない。

固定設定は`configs/quotient_seal/cross_engine_v1.yaml`、schemaは`schemas/quotient_seal_cross_engine_v1.schema.json`に置く。生成されたrun artifactは`artifacts/`以下へ保存し、Gitへcommitしない。

## wasmi adapter v1

K8-12bは`wasmi`をprocess外toolではなくRust libraryとしてembedする。workspace MSRV 1.85を維持するため、Rust 1.86を要求する`wasmi 1.1.0`ではなく、MSRV 1.83のstable `wasmi =0.46.0`をexact pinした。pinと設定は`configs/quotient_seal/wasmi_adapter_v1.yaml`へ凍結する。

adapterはABI validatorを先に通し、Eager compilation、fuel metering、fixed memory、host-call上限、MVP plus mutable-global profileで実行する。各public command後の`qseal.public.status` probeもengine設定としてexecution IDへ含める。host tapeの不足・順序違い・未消費は成功にしない。

`timeout_ms`は外側orchestratorのwatchdog契約であり、同期wasmi call単独でwall-clock timeoutを実行したとは主張しない。adapter内部の停止保証はdeterministic fuel boundである。enclosing executableのSHA-256はcallerが与え、embedded crate名だけをbinary hashとして偽装しない。

wasmi単独の再現試験は実行するが、Wasmtimeとの一致とreference differential verdictは後続Issueまで`NOT_VERIFIED`である。
