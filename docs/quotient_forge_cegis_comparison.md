# QuotientForge CEGIS Three-Way Comparison

## 目的

K7-06eはone-shot、non-incremental CEGIS、incremental CEGISを同じfrozen caseで比較する再現artifact契約を定義する。単一small caseのwall timeから一般性能やspeedupを主張するものではない。

## frozen case

三方式は次の値が完全一致しない限り比較できない。

- case ID
- synthesis problem SHA-256
- random seed
- machine state bound
- trace horizon
- candidate limit
- wall-time limit
- memory limit
- independent checker contract SHA-256

各backend runはこれらを複製して保持し、manifest構築時にfrozen caseとの一致を再検査する。

## backend run

各方式はdecision、checked candidate、metrics、resource、coreを別フィールドで保存する。`SAT`はcandidate SHA-256、独立checker済みmarker、checker artifact、1回以上のchecker callが揃わなければ受理しない。`bounded_unsat`はcandidateを持てない。

`timeout`、`resource_exhausted`、`solver_unavailable`、`not_verified`、`process_failure`、`checker_inconclusive`、`candidate_limit`は個別の`INCONCLUSIVE` reasonであり、`bounded_unsat`へ変換しない。

## resource観測境界

wall timeとpeak memoryはそれぞれ`observed`、`not_verified`、`unsupported`を持つ。数値を保存できるのは`observed`だけである。Windowsなどで信頼できるpeak memory取得を実装していない場合、推測値を入れず`NOT_VERIFIED`を保存する。

## core観測境界

core情報は`not_requested`、`unsupported`、`missing`、`rejected`、`validated`を区別する。`validated`はK7-06dのaudit artifact SHA-256と非空core sizeを必要とするが、それでもdiagnosticでありsecurity proofではない。

## comparison判定

- 三方式すべてがconclusiveで同じdecisionなら`all_conclusive_agree`。
- conclusive decisionが異なれば`conclusive_disagreement`として保存し、比較を受理しない。
- 1方式でもinconclusiveなら`incomplete`として保存し、比較を受理しない。
- 全方式が`SAT`の場合、checked candidate hashが同じか、異なるが各々検証済みかを別フィールドで示す。

性能値が同等または悪化してもartifactを破棄しない。`performance_claimed`はv1では常にfalseである。

## directory layout

writerは指定root以下だけに次を生成する。

```text
manifest.json
backends/
  one_shot/result.json
  non_incremental_cegis/result.json
  incremental_cegis/result.json
```

生成先はGit管理対象にせず、manifestと各backend artifactのdigestを実験記録として扱う。
