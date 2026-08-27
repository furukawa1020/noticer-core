# QuotientSeal Generic Family Held-out Gate v1

## 目的

16 familyをvariant単位ではなくsemantic module-family pair単位でdevelopment、validation、held-outへ分割し、baselineとfull specification oracleを同一`BenchmarkCaseInput`で比較する。

## Split

8組のvalid/negative counterpart pairをseedで決定的に回転し、4 pairをdevelopment、2 pairをvalidation、2 pairをheld-outへ割り当てる。counterpart pairがpartitionを跨ぐ場合はleakageとして拒否する。familyは8/4/4、caseは32/16/16である。

## Comparison

8 valid familyと8 negative familyの各4 variant、合計64 caseをexactly-onceで評価する。action-count baseline fixtureはextra callとduplicate actionだけを検出し、残る24 negative caseをescapeとして保存する。full specification oracle fixtureは32 validと32 negativeの期待判定を返す。

escaped negativeは成功へ丸めない。full側にescaped negative、valid誤拒否、または理由付き`INCONCLUSIVE`があればgateは`FAIL`または`INCONCLUSIVE`になる。

## Evidence boundary

本比較は`INJECTED_TEST_FIXTURE`のspecification oracleであり、wasmi、Wasmtime、実compilerをこのPRで実行した証拠ではない。runtime engine evidenceは後続評価で置き換える。toy結果はNoticer claimを代替しない。実hardwareは`NOT_VERIFIED`である。

## テスト

```bash
cargo test -p quotient-seal-benchmark --test held_out_gate
```
