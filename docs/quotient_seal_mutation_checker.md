# QuotientSeal independent mutation evaluation protocol v1

## Pipeline

K8-11cは各binary mutantを次の順序で評価する。

1. `quotient-seal-target-ir`のlocal parserを実行する。
2. 異なる実装の外部parser A・Bを同じWASMへ実行する。
3. 3 parserのdecisionを既存`reconcile_parser_decisions`で合成する。
4. 全parserがacceptした場合だけ独立checkerを実行する。

K8-10の`CommandSpec`、`CommandExecutor`、`ProcessExecutor`をそのまま再利用し、command型や
process実行境界を複製しない。各commandのprogram、完全なargs、working directory、exit code、
stdout、stderrをmutant recordへ保存する。

## Exit-code contract

外部parser:

- `0`: accepted
- `1`: rejected
- `2`: resource bound
- その他または実行失敗: not run相当

独立checker:

- `0`: mutant accepted、したがって`ESCAPED`
- `1`: mutant rejected、したがって`KILLED`
- その他または実行失敗: `INCONCLUSIVE`

parser 3系統がすべてrejectした場合だけparser-stage `KILLED`とする。すべてresource boundなら
`INCONCLUSIVE/parser_resource_bound`、decision不一致・tool不在・protocol違反は
`INCONCLUSIVE/parser_disagreement`とする。unsupportedやdisagreementをkillへ丸めない。

## CLI

各command引数には`{artifact}`を最低1回含める。3 programは同時に設定し、一部だけの設定を
拒否する。

```bash
cargo run -p quotient-seal-mutation -- \
  --seed artifacts/generated/runtime.wasm \
  --module-family noticer_reference \
  --compiler-configuration stable-o0-off-default-none \
  --parser-a-program wasm-tools \
  --parser-a-arg validate \
  --parser-a-arg '{artifact}' \
  --parser-b-program wasm-validate \
  --parser-b-arg '{artifact}' \
  --checker-program quotient-seal-independent-check \
  --checker-arg '{artifact}'
```

最後のchecker名はprotocol例であり、実機・実tool campaign完了を意味しない。実compiler、外部
parser、独立checkerを用いた37-mutant結果は実行するまで`NOT_VERIFIED`である。

