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
