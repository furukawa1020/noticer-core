# K8-15e Adaptive Fuzzer Reproduction Bundle v1

## 目的

K8-15aからK8-15dまでのseed、公開randomness、action program、coverage、corpus、counterexample、shrink trace、budget verdictを、相互参照可能なcanonical JSONへ固定する。bundle自体もdomain-separated SHA-256で完全再計算する。

## 収録artifact

| Role | 内容 |
|---|---|
| `FUZZ_REPORT` | seed、公開random word、step trace、budget verdict |
| `ACTION_PROGRAM` | 実行済みtyped action列。0 stepの`INCONCLUSIVE`では省略する |
| `COVERAGE_FEEDBACK` | 各stepのtyped coverage pointとdigest |
| `CORPUS` | retained entry、global coverage、最終digest |
| `SHRINK_REPORT` | counterexampleのattempt traceと1-minimal program |

bundle生成時はseed、context/corpus bounds、action順序、stepごとのcoverage digest、global coverage membership、最終corpus digest、violation kind/codeを照合する。digestだけ一致させた欠落artifactは受け付けない。

## Verdict保存

独立checkerで再現し1-minimal化できた反例だけを`COUNTEREXAMPLE_REPRODUCED`とする。有限10-class探索完了は`EXHAUSTED`とする。fuzzのstep/state/time bound、およびshrinkのreplay bound、unsupported、resource bound、checker disagreementは理由を失わず`INCONCLUSIVE`へ写像する。

すべて`INJECTED_TEST_FIXTURE`であり、hardwareは`NOT_VERIFIED`である。実runtimeや実deviceへの攻撃成功を示さない。

## 再現コマンド

```bash
cargo run -p quotient-seal-fuzz --example adaptive_fuzz_bundle -- artifacts/quotient_seal/adaptive_fuzz_bundle.json
```

出力先は引数で変更できる。生成JSONはGitへcommitしない。

出力例:

```text
verdict=COUNTEREXAMPLE_REPRODUCED
evidence_origin=INJECTED_TEST_FIXTURE
hardware_status=NOT_VERIFIED
steps=6
minimized_actions=1
artifact_sha256=<64 lowercase hex characters>
```
