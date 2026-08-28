# K8-15d Counterexample Shrink and Independent Replay v1

## 目的

K8-15cが発見したtyped counterexampleを、同じviolation kindとcodeを保ったまま決定的に縮約し、fuzzer targetとは別の2系統のcheckerで再生する。fixture証拠は`INJECTED_TEST_FIXTURE`、hardwareは`NOT_VERIFIED`である。

## 縮約順序

1. `CALL_DELETION`で1 actionずつ削除し、両checkerが同じviolationを再現する候補だけを採用する。
2. `INPUT_SIMPLIFICATION`でslot、malformed payload、repeat、deadline delta、fault codeを最小値へ寄せる。
3. `CONTEXT_REDUCTION`でepoch、service alias、service switchをcanonicalな最小値へ寄せる。
4. `FINAL_MINIMALITY`でもう一度1 action削除を固定点まで試す。
5. `FINAL_REPLAY`で最終programを両checkerへ再入力する。

最終programは、どの1 actionを削除しても同じtyped violationを両checkerで再現できない1-minimal programである。global minimumや意味論上の唯一解は主張しない。

## 独立判定境界

primaryとsecondaryの公開witness digestは一致を要求しないが、violation kindとcodeは一致しなければならない。一方だけがviolationを返す場合、異なるviolationを返す場合、unsupported、resource bound、replay boundは成功扱いせず`INCONCLUSIVE`としてattempt traceへ保存する。

各attemptにはphase、対象action index、前後action数、candidate program digest、両checker結果、採否を保存する。report、minimized program、attempt順序は完全再計算可能である。
