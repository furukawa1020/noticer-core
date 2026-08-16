# QuotientForge CLIと再現artifact契約

## 位置づけ

`quotient-forge`は、bounded checker、exhaustive synthesizer、repair frontier、
CAQT checker、code generator、Noticer adapterを一つの日本語診断面へまとめる。
このCLIが保存する結果はsecurity primitiveの成立を自動的に主張するものではなく、
指定bound、fixture、公開契約に対する再現可能な判定記録である。

## subcommand

| Command | Engine | 主なartifact |
|---|---|---|
| `check` | `quotient-forge-check` + Noticer adapter | `counterexample.json` |
| `synthesize` | solver-free exhaustive synthesis | `synthesis.json` |
| `repair` | bounded repair engine | `repair.json` |
| `verify` | CAQT local checker | `certificate.caqt`, `verification.json` |
| `frontier` | bounded Pareto repair | `frontier.json` |
| `generate` | CAQT-gated code generation | `generated-runtime/` |

実行例:

```bash
cargo run -p quotient-forge-cli --bin quotient-forge -- check \
  --output artifacts/k6_check \
  --seed 0 \
  --solver off
```

`--output`が既に存在する場合は上書きしない。異なる実験を同じdirectoryへ混在させず、
artifactの取り違えを防ぐためである。

## canonical manifest

各出力directoryの`manifest.json`はUTF-8・LF・固定key順・安定したfile順で保存する。
生成時刻、絶対path、host名、ユーザー名は入れない。同じtoolchain、command、seed、入力で
同じbytesになることをテストする。

manifestは次を記録する。

- schemaとpublic-only privacy contract
- command、engine、bounded status
- seed
- QuotientForge tool version
- `rustc --version`
- solver mode、検出したsolver名とversion
- 相対path、media type、byte数からなるartifact file inventory

raw PPG、個人baseline、stable identifier、private historyをartifactへ保存しない。
text artifactとpathは書込時とmanifest確定時の二段階で禁止語検査する。CAQT binaryは
public transducer、observer、utility、fault、relationの固定formatだけを受け付ける。

## solver mode

- `off`: 外部solverを探索しない。通常CIの必須mode。
- `auto`: `z3`、次に`cvc5`を探索し、無ければsolver-free engineを継続する。
- `required`: solverとversionを検出できなければ実行前に失敗する。

通常のGitHub Actions jobは`QUOTIENT_FORGE_SOLVER=off`を固定し、CLI smokeも明示的に
`--solver off`で実行する。solverありjobは`workflow_dispatch`の`run_solver`入力でだけ起動し、
研究環境差による失敗を必須CIから分離する。

## Python runnerと補助tool

```bash
python tools/run_quotient_forge.py
python tools/inspect_quotient_certificate.py path/to/certificate.caqt \
  --output artifacts/certificate_check
python tools/inspect_quotient_counterexample.py path/to/counterexample.json
```

Python側のpath操作はすべて`pathlib.Path`を使う。runnerは
`configs/quotient_forge/cli_smoke.toml`のcommand順、seed、solver modeを固定し、
各Rust manifestとは別にcanonical `run-manifest.json`を保存する。

## trust boundary

外部certificateを単独でinspectionする場合、CLIはencoded certificateから期待hashと
cost boundを復元して内部整合性を検査する。deploymentで採用可否を決める際は、独立して
配布された`ExpectedContract`をtrust anchorとして使い、自己申告値だけを信頼してはならない。
