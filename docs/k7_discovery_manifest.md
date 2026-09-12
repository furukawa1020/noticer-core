# K7 template equivalence・discovery manifest

## 目的

K7-08hは、held-outで得たtransducerについて、validityとauthor templateへの関係を分けて記録する。単なるauthor scheduleの再発見、checker未実行、resource exhaustionをnovel discoveryとして数えない。

## Canonical transducer equivalence

Rustの`machine_equivalence`はdeterministic release machineを次の順序で正規化する。

1. state、symbol、cell数、transition targetを検証する
2. initial state 0からsymbol昇順のBFSを行う
3. 発見順にstate IDを振り直す
4. initial stateから到達不能なstateを除外する
5. canonical cell列をdomain-separated SHA-256へ束縛する

このためstate IDだけの変更とunreachable padding stateはequivalentになる。reachable transitionまたはoutputが異なるmachineはdistinctになる。templateが存在しない場合でもdiscovered machine自体のwell-formedness検証は省略しない。

## Discovery classes

- `VALID_EQUIVALENT`: checker validだがauthor templateとequivalent
- `VALID_NON_EQUIVALENT`: checker validかつcanonical formがdistinct
- `VALID_UNTEMPLATED`: template不在かつchecker valid
- `EXPECTED_NONREALIZABLE`: frozen expected statusどおりのbounded negativeまたはinvalid
- `INVALID_DISCOVERY`: checker counterexample、未実行、またはmachine digest欠落
- `STATUS_DISAGREEMENT`: frozen expected statusとsynthesis結果が不一致
- `INCONCLUSIVE`: time、candidate、node、depth limitなどで未確定

template不在だけでは`VALID_UNTEMPLATED`にならない。`REALIZABLE`、`VERIFIED`、canonical machine digestの3条件が必要である。`VALID_EQUIVALENT`はnovel countへ加えない。gateはheld-outの`VALID_NON_EQUIVALENT`またはchecker-validな`VALID_UNTEMPLATED`を最低1件要求する。

## Digest chain

manifestはK7-08gの`SEALED` receiptを入力にし、次を公開する。

- calibration、corpus、split、bounds、backend bindings
- independent checker digest
- canonical equivalence checker digest
- seal receipt digest
- 8 held-out familyのtyped classification

manifestにraw machine cell、author schedule、host path、username、private biosignalを含めない。canonical manifestをheld-out resultとしてK7-08gへ渡すと、`OPENED` receiptがそのbytesを束縛する。

## 実行

```bash
python -m noticer_core.evaluation.discovery_manifest \
  --config configs/quotient_forge/discovery_gate_v1.yaml \
  --seal-ledger artifacts/quotient_forge/held_out/opening.jsonl \
  --observations artifacts/quotient_forge/held_out/observations.yaml \
  --output artifacts/quotient_forge/held_out/discovery-result.json
```

## 非主張

- canonical structural equivalenceはすべてのsemantic minimizationを証明しない
- bounded discoveryはunbounded realizabilityを意味しない
- toy corpusからdeployment一般化を主張しない
- hardware statusは`NOT_VERIFIED`である
- このmanifestだけで新規性や世界初を主張しない
