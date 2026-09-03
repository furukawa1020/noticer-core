# QuotientForge QDIMACS Contract v1

## 目的

AQRS safety-gameをQBFへ落とす前に、solver非依存の変数台帳、量化block、clause、有限bound、artifact形式を固定する。本契約はencoding syntaxの再現性を扱い、AQRS意味論のsoundnessは後続Issueで独立検証する。

## Typed variable registry

数値variable IDを呼び出し側で直接指定しない。入力はroleと非負coordinateからなる`VariableKey`で表現する。

- `MACHINE_CHOICE`: 最初のexistential block
- `PRIVATE_HISTORY_LEFT`
- `PRIVATE_HISTORY_RIGHT`
- `ENVIRONMENT_TRACE`
- `FAULT_TRACE`: 上記4 roleは中央のuniversal block
- `DEPENDENT_WITNESS`: 必要な場合だけ最後のexistential block

encoderは`block rank -> role -> coordinates`でsortして1始まりIDを割り当てる。入力配列順はIDやdigestへ影響しない。coordinateは構造indexであり、private biosignal値やstable identifierを格納してはならない。

## Canonical QDIMACS

出力順は次で固定する。

1. schema、bound、seed、typed variable台帳のcomment
2. `p cnf <variables> <clauses>` header
3. `e -> a -> optional e`の量化block
4. variable IDとpolarityでsortしたliteral
5. signed literal列でlexicographic sortしたclause

改行はLF、文字はASCIIである。同一specとseedはbyte-identicalな`problem.qdimacs`とSHA-256を生成する。

## Fail-closed validation

encoderは生成後に独立したstrict validatorへ文書を戻す。次を拒否する。

- 0個のvariable、上限超過、空coordinate、範囲外coordinate
- duplicate variable key、未登録variable参照
- duplicate literal、tautological clause、duplicate clause
- 非integer literal、0 terminator不備、variable範囲外literal
- headerと実variable/clause数の不一致
- 未量化variable、重複量化、非昇順ID
- `e -> a -> optional e`以外の量化順
- 非canonicalなliteralまたはclause順

空clause自体はCNFのbounded contradictionを表す正規な入力として許可する。

## Artifact

`metadata.json`はschema version、plant/machine state bound、horizon、action count、seed、typed registry、quantifier blocks、variable/clause count、QDIMACS SHA-256をcanonical JSONで保存する。生成物は`artifacts/`配下へ出力し、Gitへcommitしない。

## 非主張

- QDIMACS syntaxの決定だけからAQRS encodingのsoundnessを主張しない。
- QBF solverの正しさやSAT/UNSATをこの段階で扱わない。
- bounded negativeをglobal unrealizableへ昇格しない。
- QBF導入自体を研究新規性として扱わない。
