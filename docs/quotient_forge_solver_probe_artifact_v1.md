# QuotientForge Solver Probe and Result Artifact v1

## 目的

外部SMT solverをversion文字列だけで信頼せず、必要capabilityと実行結果の意味を再現可能な証跡へ固定する。
solverは候補生成器であり、security oracleではない。

## 選択前probe

実binaryは次の3 probeがすべて成功した場合だけavailableになる。

- `INTEGER_MODEL`: QF_LIAの整数制約を解き、指定したmodel値を返す。
- `OPTIMIZATION`: 整数目的関数を最小化し、最適model値を返す。
- `REASON_UNKNOWN`: `get-info :reason-unknown`を受理して応答する。

probe artifactはscript、stdout、stderrそのものを保存せず、それぞれのSHA-256を保存する。timeout、非zero exit、出力上限、期待外応答は別diagnosticとしてfail closedにする。

## 5値result taxonomy

結果は次の5値を保持し、相互変換しない。

- `SAT`
- `UNSAT_AT_BOUND`
- `UNKNOWN`
- `TIMEOUT`
- `MALFORMED`

`UNSAT_AT_BOUND`は記録した有限search boundにだけ有効であり、global `UNREALIZABLE`を意味しない。`UNKNOWN`はsolverが明示した結果であり、構文不明な`MALFORMED`とは区別する。

## SATの独立検証

`SAT` artifactの生成には既存independent checkerの`ACCEPTED`が必須である。`REJECTED`または`NOT_APPLICABLE`のSAT候補はartifact constructorが拒否する。solver出力だけから有効なwitnessを主張できない。

## Canonical artifact

result artifactは次をcanonical JSONへ保存する。

- solver、version、platform
- selected binary SHA-256、solver matrix SHA-256
- programを含む実argv
- timeout、seed、有限search bound
- query、stdout、stderrのSHA-256
- 5値result、independent checker result、diagnostic

同じmetadata、query、bounded outputから同じbyte列とartifact SHA-256を生成する。生成先は`artifacts/`配下を想定し、Gitへcommitしない。

## 非主張

- solver自体の正しさは保証しない。
- bounded `UNSAT_AT_BOUND`からunbounded completenessを主張しない。
- capability probeの成功から、probe外の全SMT-LIB機能を保証しない。
