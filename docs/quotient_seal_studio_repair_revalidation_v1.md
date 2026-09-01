# QuotientSeal Studio Repair Revalidation v1

## 目的

QuotientPad Revalidation Bayは、resource-only counterexampleから生成した修復候補を、元のsecurity checker群と独立performance gateへ戻して再評価するsoftware fixtureである。修復候補、security再検証、性能測定を単一のPASSへ潰さない。

## Repair candidate

候補はRustの`QuotientPadCandidate`と同じ構造を持つ。

- `version`
- `operations`: relation pair、event index、resource axis、normalization kind、pad side、amount
- `overhead`: operation count、added instructions、added fuel、bounded loop iterations、fixed scratch bytes
- SHA-256 digest

利用するresource axisは`OPCODE`、`BRANCH`、`MEMORY_ADDRESS`、`IMPORT`、`FUEL`、`MEMORY_PAGES`の6種に固定する。

## Security revalidation

修復後はrelation、malicious context、resource trace、utility、deadlineを再検証する。

- 全gateが成立した固定fixtureだけを`VALID`とする。
- utilityまたはdeadlineを変えた候補は、resource traceが揃っても`INVALID`とする。
- resource bound、unsupported、engine disagreement、証拠欠落は`INCONCLUSIVE`とする。
- `VALID`は固定fixtureに対する`BOUNDED_SECURITY_EVIDENCE`であり、一般的な安全性証明ではない。

## Performance gate

performance gateはbaseline/candidate statisticsとbudget planをdigestで結び、`PASS`、`FAIL`、`INCONCLUSIVE`を返す。ただし判定には常に`NOT_A_SECURITY_VERDICT`を付与する。

Studioは次の交差fixtureを必須とする。

| Security | Performance | 意味 |
|---|---|---|
| VALID | PASS | 2つの独立gateが成立 |
| INVALID | PASS | 性能成立はsecurity失敗を上書きしない |
| VALID | FAIL | security成立は性能budget超過を隠さない |
| INCONCLUSIVE | INCONCLUSIVE | 証拠不足を成功へ昇格しない |

## Artifact chain

`ATTACK_FIXTURE → COUNTEREXAMPLE → QUOTIENT_PAD → REVALIDATION`をsecurity系のchainとし、`BASELINE_STATISTICS + CANDIDATE_STATISTICS → PERFORMANCE_GATE`を性能系のchainとする。最後に両者を`REPAIR_BUNDLE`が参照する。各参照はSHA-256で固定する。

## Claim boundary

- `evidence_origin = SOFTWARE_FIXTURE`
- `hardware_status = NOT_VERIFIED`
- Polar Verity Sense実機での性能、biosignal取得、security成立は主張しない。
- candidate new primitiveの検討用であり、world-firstを断定しない。

