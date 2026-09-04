# QuotientForge counterexample signature v1

## 目的

incremental CEGISで同じ反例を何度も登録しないため、AQRS checkerのraw `Counterexample`から公開可能で決定的な署名を作る。署名は反例のproofではなく、重複・prefix・subsumptionを監査するためのindexである。

## 公開境界

署名に含める情報:

- violation kind、side、action、obligation
- observerとcausal field名
- public input ID、public symbol、fault ID
- release presence、field名、action構造
- slotとtrace順序
- 正規化したrepair candidate

署名に含めない情報:

- release field value
- private-history identifier
- checkerのcombined state ID
- biosignal、baseline、subject/session identifier

field値をそのままhash化することもしない。低entropy値の辞書攻撃やrun間linkabilityを避けるためである。`public_symbol`はchecker modelで公開と宣言済みであることを信頼境界とする。

## canonical化

actionとrepair candidateは意味的に順不同なためsortし、repair candidateはdeduplicateする。trace step自体の順序と重複actionの多重度は意味を持つため保持する。canonical JSON payloadへSHA-256を適用し、schema versionとともに保存する。

schema:

```text
noticer.quotient_forge.counterexample_signature.v1
schemas/quotient_forge_counterexample_signature_v1.schema.json
```

## 関係

- exact duplicate: canonical counterexample全体が一致する。
- strict prefix: violation contextが同一で、一方のtraceが他方の真のprefixである。
- subsumption: exact duplicateまたはstrict prefixである。

violation contextにはkind、observer、value-redacted observation shape、causal field、repair candidateを含める。異なるkind、public input、action、observerを横断したsubsumptionは禁止する。

`CounterexampleCatalog`は既存entryが新規entryをsubsumesする場合に追加を抑止する。新しい短いprefixが既存の長いentryをsubsumesする場合は長いentryを除き、canonical順へ並べ直す。

## Security boundary

この署名だけでblockerを再構成または受理してはならない。次段のtyped blockerはsource candidate hash、problem hash、epoch、自己除外検査を別途必要とする。公開情報を同じ形に正規化した異なるraw反例が同じ署名になることは意図したprivacy境界であり、source candidate provenanceなしでsolver assertionを省略する根拠にはしない。

## Falsification conditions

- canonical bytesにprivate field valueまたはcombined state IDが現れる。
- repair/action入力順だけでdigestが変わる。
- 異なるviolation kindまたはpublic inputをsubsumesする。
- digest改変を`validate_digest`が検出しない。
- signature一致だけでcandidateまたはblockerをsecurity-validとして受理する。

これらのいずれかが成立する実装はfail closedとし、incremental sessionへ接続しない。
