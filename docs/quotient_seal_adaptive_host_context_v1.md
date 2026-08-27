# QuotientSeal Adaptive Host Context v1

## 目的

adaptive malicious host fuzzerが生成できるpublic action grammarとbounded context stateを固定する。既存`quotient-seal-context`の`ContextFamily`と`ContextCommand`を直接再利用し、別のcontext semanticsを複製しない。

## Action grammar

tick、reset、handoff、malformed、repeat、stale slot、future slot、fault、reconnect、service switchをtyped actionとして扱う。各actionは既存context familyとcommand kindへ決定的に変換される。zero repeat、zero slot delta、zero fault、範囲外service、自己service switchは拒否する。

## State boundary

stateはstep、public slot、service alias、connection、repeat/fault/event count、直近public observation digestだけを保持する。遷移入力はpublic actionとpublic observationだけであり、private observation、private trace、secret、stable identifierを持たない。

step、service、repeat、fault、public eventの各boundを超える遷移は`StateBound`またはtyped errorとしてfail-closedにする。

## Artifact

programはseed、bounds、action列、`INJECTED_TEST_FIXTURE`、`NOT_VERIFIED`をcanonical JSONへ格納し、`QSFUZZC1` envelopeとdomain-separated SHA-256で保護する。trailing bytes、digest tamper、non-canonical JSONを拒否する。

実runtime、実compiler、実deviceへのattack結果ではなく、world-firstを主張しない。

## テスト

```bash
cargo test -p quotient-seal-fuzz --test action_state
```
