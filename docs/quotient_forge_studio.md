# QuotientForge StudioとWASM small-model checker

## 位置づけ

QuotientForge Studioは、違反specからcounterexample、repair、cost frontier、certificate rejection、
generated Rust previewまでの説明経路をbrowserで再現するinteractive interfaceである。
研究上の中心貢献、native checkerの代替、deployment trust anchor、または外部solver frontendとして
扱わない。

## Architecture

```text
Monaco spec editor
  -> TypeScript syntax diagnostics / bounded flag compiler
  -> Rust raw-WASM small-model checker
  -> counterexample / repair / cost projection
  -> preview certificate / generated Rust explanation
```

`crates/quotient-forge-studio-wasm`は`wasm32-unknown-unknown`向けのraw C ABIを公開する。
`wasm-bindgen`、external solver、network service、JS判定fallbackへ依存しない。

- `qf_check`: security、authorization、deadline、recovery、transition totalityをbounded判定
- `qf_repair`: small-model violation flagをpublic-safe candidateへ変換
- `qf_cost` / `qf_frontier_cost`: 3つの説明用frontier pointを返す
- `qf_verify_certificate`: preview値のtamper一致を拒否する

Studioのcertificate interactionはrejection semanticsのdemonstrationであり、cryptographic CAQT検証を
主張しない。実際のcode generationと採用判断は、独立したExpectedContractを使うnative
`quotient-forge-caqt` checkerで行う。

## Browser boundary

browser modeは次へ固定する。

- horizon 1から8
- 単一の説明用contract
- 外部SMT solverなし
- bounded exhaustive small-model resultだけ
- raw PPG、baseline、private evidence、stable identifierを入力・保存しない
- telemetryをCIで無効化

syntax parserは未知clauseと必須clause欠落をMonaco markerでunderlineする。syntax error時はRust
checkerへ不完全modelを渡さず、semantic counterexampleを生成しない。

## Interaction

初期specは意図的にprivate cadence、unauthorized action、missed deadline、missing recoveryを含む。

1. `Run checker`でRust WASMが最初のcausal violationを返す。
2. paired-world graphでobserver divergenceを表示する。
3. `Synthesize repair`でfixed cadence、authorized action、met deadline、present recoveryへ変換する。
4. 3つのnon-dominated説明用cost pointからRust previewを切り替える。
5. preview certificateの1 bitを変更し、Rust WASM rejectionを確認する。

## Build

Node.js 24とRust `wasm32-unknown-unknown` targetを使う。

```bash
cd studio
npm ci
npm run check
npm run build
```

`npm run build`は`scripts/build-wasm.mjs`を先に実行し、workspaceのRust crateを`--locked`かつ
release profileでcompileする。生成された`studio/public/wasm/*.wasm`、`.astro/`、`dist/`、
`node_modules/`はcommitしない。

GitHub Actionsの`studio` jobは次を独立して必須実行する。

- `npm ci`
- `npm run check`
- `npm run build`

CSSはdesktopの二段workbenchからtablet/mobileの単一columnへ変形し、同じdiagnostic、repair、
frontier、certificate情報を落とさない。motion reduction preferenceではload animationを無効化する。
