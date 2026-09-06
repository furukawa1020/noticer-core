# QuotientForge Preservation Obligations

## 目的

K7-07bはK7-07aのaction quotientがcomplete observer trace、hard utility、fault behaviorを保存するかを別々の義務として検査する。action semanticsが一致するだけではreductionを有効化しない。

## 入力契約

各source stateは次を持つ。

- 順序付きobserver event trace
- canonical utility-obligation digest set
- fault trigger、target source state、observable effectのtransition set

全quotient stateのpreservation dataがちょうど1件ずつ必要である。欠落、重複、未知state、未知fault targetはartifact上のPASSへ変換せずerrorで停止する。

## 三つの保存義務

`observer_trace`はevent順を含むcomplete declared trace digestを比較する。`utility`はhard obligation集合のdigestを比較する。`fault`はtarget source stateをK7-07aのquotient classへ写してからtransition集合を比較する。この正規化により、同じtarget classの異なるmemberを指す遷移は意味的に同じものとして扱う。

各classのmemberをsource index順に並べ、全unordered pairを検査する。最初の不一致だけをobligation別の最小witnessとして保存する。公開witnessはclass ID、member ordinal、左右signature digestだけを持つ。元source pairはserializeしないprocess内mapから取得する。

## fail-closed判定

- 全3義務が全pairで一致した場合だけ`PASS`かつ`reduction_enabled=true`。
- 1件でも不一致なら`FAIL`かつreduction無効。
- 事前固定pair limitを超える場合は全義務を`INCONCLUSIVE / pair_limit`としreduction無効。

timeoutや不足情報をPASSへ変換しない。v1は決定論的pair limitだけを扱い、wall-clock timeoutは後続実backend ablationで別に記録する。

## 非主張

この検査はbounded input contract上のcongruence checkであり、無制限traceの証明ではない。performance改善、solution-set同値性、lift後candidateの妥当性は後続Issueで独立に検査する。
