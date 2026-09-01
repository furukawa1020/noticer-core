# QuotientSeal Studio Relational Trace Microscope v1

## 目的

K8-17cは、source transducer stepとtarget WASM small-stepを同じindexで追跡し、state relation、stuttering、API/control/instruction/memory/resource observationを監査可能にする。

Microscopeはtraceを生成・検証するauthorityではない。native relation validatorが生成した公開trace summaryを説明するviewであり、private memoryやbiosignalをbrowserへ渡さない。

## Typed trace

各stepは次だけを持つ。

- 連番index
- source stateとpublic transition
- target program counterとopcode
- relation record番号
- `MATCH`、`STUTTER`、`DIVERGED`
- 公開observer channel別summary

observer channelは`API`、`CONTROL`、`INSTRUCTION`、`MEMORY`、`RESOURCE`である。memory表示は公開領域のaddress/width summaryだけを想定し、byte contentを持たない。

## 三値判定

最初の`DIVERGED`が存在すれば`INVALID`とし、そのindexをdeterministic focusにする。divergenceがなくterminationが`COMPLETE`なら、宣言済みfixture bound内で`VALID`とする。

terminationが`RESOURCE_BOUND`、`UNSUPPORTED`、`ENGINE_DISAGREEMENT`なら、divergenceがなくても`INCONCLUSIVE`である。省略表示やobserver非選択をVALIDの根拠に使わない。

## Bounded virtualization

typed artifactは最大10,000 stepに制限する。DOMへ描画するのは選択indexを中心とした最大9 stepだけであり、前後の省略件数を明示する。

```text
omitted_before + rendered_steps + omitted_after = total_steps
```

この不変条件により、大きなfixtureでbrowserを停止させず、「表示されていないstepも監査した」という誤表示を防ぐ。

## Observer projection

channel selectorはimmutableなstepから新しいprojectionを作る。元traceのobservation mapを書き換えず、選択されていないeventを削除済みartifactとして保存しない。selector変更はsecurity verdictも変更しない。

## UI

range scrubber、bounded window、source/target lane、relation glyph、selected-state card、visible-event cardを同期する。

- `≈`と`MATCH`
- `…`と`STUTTER`
- `≠`と`DIVERGED`

形状、文言、色を併用する。first divergence jump、congruent fixture、divergence fixtureをkeyboardとtouchで操作できる。mobileではtimeline detailを1列へ再配置する。

fixtureはUIとtrace contractのsmoke evidenceであり、科学的攻撃結果、実機測定、unbounded refinement proofではない。
