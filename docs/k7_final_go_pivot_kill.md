# K7 final GO / PIVOT / KILL gate v1

K7-16gはK7-00で凍結したresearch contractを変更せず、全software evidenceと32件のreviewer rejection
argumentから最終判断を生成する。policyはcontract SHA-256とgate-registry SHA-256の両方を固定し、現在の
contractから再計算した値と一致しなければ判定を開始しない。

判定順序は`KILL > PIVOT > GO`である。KILL criterionまたはfatal rejectionが1件でもtriggerされれば、
他の成功数に関係なくKILLとなる。PIVOT criterion、未達・不明GO criterion、OPEN rejection argumentが
1件でもあればPIVOTとなる。全14 GO criteriaがartifact digest付きでtrue、全PIVOT/KILL criteriaがfalse、
32 rejection argumentsがすべてADDRESSEDの場合だけGOとなる。

特に`independent_replication_verified`は必須GO criterionであり、CI green、artifact完成、unit test数で
代替できない。CI statusはevidence schemaに存在せず、追加すると拒否される。hardware statusは常に
`NOT_VERIFIED`である。

```bash
python -m noticer_core.replication.k7_final_decision blank-evidence \
  --output artifacts/k7_replication/final-evidence.json

python -m noticer_core.replication.k7_final_decision decide \
  --evidence artifacts/k7_replication/final-evidence.json \
  --output artifacts/k7_replication/final-decision.json
```

priority wordingは次に限定する。

> to the best of our literature review, we found no prior work combining these exact semantics

本判定はbounded research decisionであり、security proof、完全な文献・特許調査、hardware検証ではない。
generated evidenceとdecisionは`artifacts/`配下へ出力しGitへcommitしない。
