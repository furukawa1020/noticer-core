# QuotientSeal Studio Adversarial Scenario Lab v1

## 目的

Adversarial Scenario Labは、QuotientSealの反例をWISSデモ上で再現し、原因、観測面、最小action列、独立replay、artifact digestの関係を一画面で確認するためのsoftware fixtureである。これは実機評価や網羅的な安全性証明ではない。

## 入力境界

- action列はRustの`AdaptiveHostAction`に対応する固定paletteだけから構成する。
- action数は1以上16以下に制限する。
- mutationはRustの`MutationOperator` taxonomyに存在する固定シナリオだけを使う。
- 任意JavaScript、Wasm、shell、自由入力コードは実行しない。
- seed、効果、観測面、必要action列はfixture内に固定する。

## 判定規則

`REFERENCE_REPLAY`と`INDEPENDENT_REPLAY`が同じ反例を再現した場合だけ`INVALID`とする。action列が反例条件を満たさない場合は`INCONCLUSIVE`とし、反例が見つからなかったことを一般的な安全性へ昇格しない。engine間で結果が異なる場合も必ず`INCONCLUSIVE`とする。

3つの固定攻撃fixtureを持つ。

| Scenario | MutationOperator | Observer | 反例 |
|---|---|---|---|
| Extra host call | `extra_host_call` | API | 追加host call |
| Private-dependent trap | `private_dependent_trap` | CONTROL | termination差 |
| Resource-only leak | `opcode_cost_inflate` | RESOURCE | API一致下のfuel差 |

`Engine disagreement`は負のcontrolであり、攻撃成功件数へ含めない。

## 縮約と再現性

action縮約は固定順序の削除を繰り返し、反例条件を維持する1-minimal列を返す。各結果はfixture、mutant、counterexample、replayの順にSHA-256で参照し、同じseedとaction列から同じdigest chainを再構成する。

## Claim boundary

- `evidence_origin = INJECTED_TEST_FIXTURE`
- `hardware_status = NOT_VERIFIED`
- `security_interpretation = BOUNDED_SECURITY_EVIDENCE`
- Polar Verity Senseでの動作、実時間性能、実機biosignal、一般的な安全性は主張しない。
- 本表示はcandidate new primitiveの検討を支援するもので、world-firstを断定しない。

