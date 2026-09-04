# QuotientForge bounded backend comparison

## 目的

K7-05eは、同じ凍結済み`SynthesisProblem`をexhaustive、SMT、QBFで評価し、decisionと検証済みcandidateの対応をmachine-readable artifactとして残す比較harnessである。これはbounded differential testであり、一般的なsolver性能やunbounded realizabilityを主張しない。

## 実行

solver-free smoke:

```bash
cargo run --locked -p quotient-forge-cli --bin quotient-forge -- compare-backends --output artifacts/k7-05e-smoke --seed 0 --solver off --symmetry-breaking on
```

`--solver off`ではexhaustiveとin-process QBF reference evaluatorを実行し、SMTを`NOT_RUN`として記録する。`--solver auto`または`--solver required`では、次の固定matrixとinstallation rootからSMT runtimeを構成する。

```text
QUOTIENT_FORGE_SOLVER_MATRIX=configs/quotient_forge/solver_matrix_v1.json
QUOTIENT_FORGE_SOLVER_ROOT=artifacts/quotient-forge-solvers
```

実CAQEを使用する場合は、検証済みinstallationの両方を指定する。

```text
QUOTIENT_FORGE_QBF_ROOT=<installation root>
QUOTIENT_FORGE_QBF_RECEIPT=<install.json>
QUOTIENT_FORGE_QBF_MANIFEST=configs/quotient_forge/qbf_solver_manifest_v1.json
```

片方だけの指定は拒否する。Windowsの実CAQE経路は`NOT_VERIFIED`であり、現時点では実行を拒否する。solver未指定時のQBF参照評価は小規模差分試験専用で、variable上限を超えた場合は`RESOURCE_EXHAUSTED`となる。

## 出力契約

```text
comparison.json
backends/exhaustive/result.json
backends/smt/result.json
backends/qbf/result.json
manifest.json
```

`comparison.json`は`noticer.quotient_forge.backend_comparison.v1`に従う。schemaは`schemas/quotient_forge_qbf_backend_comparison_v1.schema.json`に固定する。QBFのSAT candidateは、solver種別に関係なくK7-05dのdecoderと独立AQRS checkerを通過した場合だけ`CANDIDATE_VERIFIED`になる。

statusは次を区別する。

| Status | 意味 |
|---|---|
| `CANDIDATE_VERIFIED` | bounded candidateが独立checkerを通過した |
| `UNREALIZABLE_WITHIN_BOUNDS` | 指定bound内の否定であり、一般不可能性ではない |
| `TIMEOUT` | wall-clock上限に達した |
| `RESOURCE_EXHAUSTED` | candidate、変数、出力などのresource上限に達した |
| `SOLVER_UNAVAILABLE` | 指定solverを利用できない |
| `SOLVER_UNKNOWN` | solverがunknownを返した |
| `MALFORMED_OUTPUT` | encoding、出力、candidate契約が不正だった |
| `NOT_RUN` | backendを明示的に実行しなかった |

## resource観測境界

各backendはwall time、QDIMACS変数・節数、CEGIS rounds、exhaustive候補数・checker回数を該当する範囲で記録する。Linuxのpeak memoryはharness processの`VmHWM`であり、子solver単体の最大RSSではない。Windowsのpeak memoryは未計測のため`null`、scopeは`NOT_VERIFIED`とする。

wall timeとpeak memoryは観測値なのでrun間で同一byte列になるとは限らない。JSON field、status taxonomy、hash、backend directory構造が再現契約である。

## symmetry設定

`--symmetry-breaking on|off`は要求値をartifactへ保持する。v1 compilerではcanonical `ReleaseMachine`列挙が常時有効であり、`symmetry_breaking_effective`は`CANONICAL_RELEASE_MACHINE_V1_ALWAYS_ON`である。したがって`off`は完全なsymmetry ablationを意味せず、性能差の根拠に使用してはならない。

## falsification条件

- exhaustiveとQBFのconclusive decisionが不一致になる。
- QBF SATが独立checkerを通らずにacceptedとして公開される。
- universal traceまたはdependent witnessがrelease-machine candidateへ混入する。
- timeout、resource exhaustion、bounded negativeが同じstatusへ潰れる。
- solver-free実行が外部binaryを暗黙に起動する。
- 異なるQDIMACSを同じhashとして記録する。

これらのいずれかが成立したartifactは研究結果として利用しない。
