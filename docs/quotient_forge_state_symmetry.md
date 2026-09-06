# QuotientForge State-Renaming Symmetry

## 目的

K7-07cはmachine state名だけが異なる同型candidateをcanonical representativeへ写す。transitionとoutput semanticsは変えず、探索上の重複だけを除く。

## canonical numbering

initial stateを0とし、input symbol昇順のBFSでreachable stateへ番号を付ける。deterministic labeled transitionを使うため、このreachable-first順は元state番号に依存しない。

unreachable stateは単純な元ID順にしない。事前固定上限内ですべてのpermutationを列挙し、reachable prefixと結合して得られる全machine encodingの辞書最小値を採用する。上限超過やfactorial overflowはfail closedし、近似representativeを返さない。

## isomorphism witness

`StateRename`はoriginal stateからcanonical stateへの全単射である。validatorはinitial state、全transition target、symbol、output digestを照合する。witnessはprocess内resultから取得できるが、state IDを安定artifactへ残さないためv1 artifactには永続化しない。

## independent checker gate

元machineとcanonical machineを同じ契約のcheckerへ別々に渡す。両方がconclusiveかつ同じdecisionの場合だけ`decision_preserved=true`、`canonicalization_enabled=true`とする。不一致またはいずれかが`INCONCLUSIVE`ならcanonicalizationを無効化する。

## 非主張

これはbounded finite transducer向けのcanonicalizationであり、graph isomorphism一般への新規アルゴリズムではない。performance効果とsolution-set同値性は後続Issueで実測・検査する。
