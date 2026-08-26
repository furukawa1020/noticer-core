# QuotientSeal Generic Benchmark Contract v1

## 目的

Noticer固有のbiosignalやtoken型へ依存しないaction-quotient robust-compilation benchmarkの共通入力を固定する。baselineとfull QuotientSealは同じ`BenchmarkCaseInput`を消費し、evaluator固有の入力差による比較の混同を防ぐ。

## Family registry

valid familyはprivate deadline admission、medical alert class、smart-home action、private scheduler、credential release、fraud review、safety interlock、resource admissionの8系統である。negative familyはextra call、private trap、resource leak、exported memory、reset leak、state corruption、duplicate action、handoff carryoverの8系統である。

各familyはpublic action class、private predicateの分類名、observer surface、resource budget、variant count、seed、期待判定を持つ。private predicateの実値やprivate traceは含めない。

## 判定境界

結果は`VALID`、`INVALID`、`INCONCLUSIVE`の三値で扱う。unsupported、resource bound、engine disagreementは理由付き`INCONCLUSIVE`であり、成功へ丸めない。negative familyは人工fixtureであり、実compilerや実serviceの脆弱性発見を意味しない。

## Canonical artifact

registryはUTF-8 canonical JSONを`QSBENCH1` envelopeへ格納し、domain-separated SHA-256を付与する。family順序、16 family、kindとexpected verdict、resource bound、`INJECTED_TEST_FIXTURE`、`NOT_VERIFIED`をdecode時に再検証する。trailing bytesとdigest tamperはfail-closedで拒否する。

## 検証境界

このgeneric benchmarkのtoy成功はNoticer統合の実証を代替しない。実sensor、BLE、Polar Verity Sense、TEE、実hardwareは`NOT_VERIFIED`である。world-firstを主張しない。

## テスト

```bash
cargo test -p quotient-seal-benchmark --test contract
```
