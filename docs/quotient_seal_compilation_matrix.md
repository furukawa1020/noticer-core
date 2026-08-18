# QuotientSeal compilation matrix v1

## 目的

K8-10は、K7が生成する`no_std` Rust runtimeを複数の`rustc`、最適化、LTO、
codegen unit、`wasm-opt`条件で変換し、同一の独立checkerへ渡す実験契約を固定する。
compilerとoptimizerの正しさを仮定せず、変換後artifactがaction quotientを保存したかを
外部checkerの結果として記録する。

これはQuotientSealの防御効果や優先性を示す実験ではない。2026-08-18時点で実機を含む
全matrix実行は`NOT_VERIFIED`であり、この文書は再現可能な評価器の契約を定める。

## 信頼境界

- `rustc`、`rustup`、`wasm-opt`はTCBへ含めない。
- 各binaryの解決path、SHA-256、version出力、完全な引数列、targetをmanifestへ残す。
- `ACCEPT`は、同一入力を2回変換したbyte列が一致し、独立checkerがexit code 0を返した場合だけ発行する。
- 独立checkerのexit code 1は`REJECT`、実行不能、tool不在、build失敗、未対応結果は`INCONCLUSIVE`とする。
- 最適化条件が成功することを前提にしない。失敗も観測結果として保存する。

## 固定matrix

`configs/quotient_seal/compilation_matrix_v1.yaml`はJSON互換YAMLとして記録する。
これにより追加parserをTCBへ持ち込まず、厳密なunknown-field拒否を行う。

- stable: `1.93.0`
- held-out nightly: `nightly-2025-03-15`
- target: `wasm32-unknown-unknown`
- `opt-level`: `0`, `1`, `2`, `3`, `s`, `z`
- LTO: `off`, `thin`, `fat`
- codegen units: default, `1`
- `wasm-opt`: none, `O1`, `O2`, `Os`, `Oz`
- configuration数: 14

nightly条件は開発時の合否調整に使わないheld-out集合である。manifestの`held_out`を維持した
まま、後続のcompiler mutation評価へ再利用する。

## 再現性判定

各configurationを同じsourceと引数で2回、異なるoutput pathへ変換する。最終Wasmの
SHA-256が一致すれば`BYTE_IDENTICAL`、異なれば`DIVERGED`、tool失敗などで比較できなければ
`NOT_MEASURED`と理由を記録する。`DIVERGED`ではcheckerの結果を安全側に保留し、全体を
`INCONCLUSIVE`とする。

## CLI

計画だけをJSONへ出す例:

```bash
cargo run -p quotient-seal-matrix -- plan \
  --configuration stable-o0-off-default-none \
  --source artifacts/generated/src/lib.rs \
  --checker-program node \
  --checker-arg artifacts/generated/wasm-validation.mjs \
  --checker-arg '{artifact}'
```

実行する場合は`plan`を`run`へ変更する。成果物と`manifest.json`は
`artifacts/quotient_seal_matrix/<configuration>/`へ保存し、Gitへcommitしない。

## 反証可能性

次のいずれかを観測したconfigurationは成功として数えない。

- 同一条件の2回の最終byte列が一致しない。
- compilerまたはoptimizerが失敗する。
- tool binaryのhashまたはversionを記録できない。
- 独立checkerがartifactを拒否する。
- checkerが起動できない、または0/1以外のexit codeを返す。

