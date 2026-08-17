# AQRS Independent Semantics Oracle

## Status

本実装は、AQRSの有限モデルに対する第二の実行可能semanticsです。Rust checkerの正しさを証明するものではなく、同じ実装誤りを自己確認する循環を減らすための差分検査面です。

共有するのは[`aqrs-check-model-v1`](../schemas/aqrs_checker_model.schema.json)のcanonical JSONだけです。Python oracleはRust crate、FFI、生成済みCAQT、Rust側の探索コードをimportしません。Rust adapterも判定規則を追加せず、JSONから既存`CheckerModel`への変換と公開結果への射影だけを担当します。

## 判定対象

Python oracleは次を決定的なBFS順で有限全探索します。

- action-equivalentかつprivate-distinctな初期状態対
- 全public inputに対する全域遷移
- observerごとのrelease presence、visible field、action列
- authorized actionの時区間、exactly-once、deadline
- recoverable faultから生成されるrecovery obligation
- node、depth、wall-clockの資源上限

最初に発見した反例には、slot、input、左右状態を含む最短traceを付けます。入力不正は`invalid`、探索打切りは`inconclusive`であり、どちらも`verified`へ昇格しません。

## 差分判定

実行例:

```bash
python -m noticer_core.evaluation.aqrs_differential model.json \
  --output artifacts/quotient_forge/oracle/report.json
```

Windows PowerShellでも引数は同一です。path処理はPython、Rustともにplatform separatorを仮定しません。

比較面は次の固定fieldです。

```text
status, category, slot, observer, side, causal_field,
obligation, action, reason, checked_horizon
```

一致時だけ`AGREE`です。不一致は`UNRESOLVED`となりCLIは終了code 3を返します。多数決、Rust優先、Python優先、timeoutの安全性成功への変換は行いません。差分reportには入力bytesのSHA-256を記録しますが、private history本文やlocal pathは転記しません。

## Mutation adequacy

smoke corpusは次の10種の意図的なchecker mutantを殺せることを要求します。

1. release presenceの観測省略
2. visible fieldの観測省略
3. observed actionの観測省略
4. 左runのutility検査抑止
5. 右runのutility検査抑止
6. unknown obligationの許容
7. duplicate actionの許容
8. authorized deadlineの抑止
9. recovery activationの抑止
10. node limitのverified昇格

これによりobserver omission、utility suppression、fault/recovery mismatchを別々の反証経路として保持します。mutation scoreはoracleの形式証明ではありません。

## Reproducibility

```bash
python -m pytest tests/test_aqrs_oracle.py tests/test_aqrs_differential.py
cargo test -p quotient-forge-check
```

生成reportは`artifacts/`配下へ置き、Gitへcommitしません。モデルformatまたは比較面を変える場合はversionを上げ、既存結果を上書き解釈しません。

## Non-claims

- 独立実装の一致はsoundness proofではありません。
- bounded verificationはunbounded securityを意味しません。
- wall-clock timeoutは再現可能な否定結果ではありません。
- この実装だけから新規性、優先権、world-firstを主張しません。
- 差分が出た場合、片方を正解と仮定せず両方を未確定として停止します。
