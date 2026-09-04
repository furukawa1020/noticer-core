# QuotientForge typed blocker provenance v1

## 目的

counterexample-derived blockerを匿名のsolver clauseとして扱わず、違反class、frozen problem、source candidate、counterexample signature、epochへ結び付ける。blockerは探索を削減するhintであり、security proofではない。

## class

| Class | Counterexample |
|---|---|
| `SECURITY` | observer trace divergence |
| `UTILITY` | unauthorized action、duplicate action、missed deadline |
| `FAULT` | recoverable fault obligation violation |

classは重ならない。今後のincremental sessionとnamed assertionはclass別namespaceを使用する。

## provenance

`noticer.quotient_forge.typed_blocker.v1`は次を記録する。

- `problem_sha256`: frozen synthesis semantics
- `source_candidate_sha256`: blockerを生成したrelease machine
- `counterexample_sha256`: K7-06aのvalue-redacted signature
- `epoch`: incremental session generation
- `blocker_sha256`: artifact全体のintegrity digest
- canonical decision assignments

problem fingerprintではprivate-history文字列をhashへ直接入れず、出現順の同値類番号へ置換する。これによりprivate identity labelを保持せず、checkerに必要な「同じか異なるか」を固定する。他のpublic semantics、utility/fault contract、observer contract、release alphabetは長さ付きcanonical encodingへ含める。

## acceptance boundary

blockerをsessionへ追加する前に次をすべて満たす必要がある。

1. schema、digest、assignment順が妥当である。
2. current problem hashとepochが一致する。
3. source candidate hashが一致する。
4. clauseがsource candidateを実際に除外する。

artifactから復元したblockerも同じ検査を通す。signature一致だけでは受理しない。

## over-exclusion audit

`audit_candidate`はblockerが別candidateを除外する場合、そのcandidateを独立AQRS checkerへ渡す。verified candidateを除外する場合は`OVER_EXCLUDES_VERIFIED_CANDIDATE`相当として検出し、incremental探索は安全側へ停止しなければならない。checker resource exhaustionもvalid/invalidへ丸めない。

## status boundary

- `NotExcluded`: blocker対象外
- `SourceCandidateExcluded`: provenanceどおりsourceを除外
- `InvalidCandidateExcluded`: 独立checkerでもinvalidな別candidateを除外
- `OverExcludesVerifiedCandidate`: blockerが不健全
- `CheckerInconclusive`: audit resource内で判定不能

## falsification conditions

- source candidateを除外しないblockerが生成される。
- problemまたはepoch変更後もblockerがvalidになる。
- artifact改変がdigest検査を通る。
- private-history文字列がartifact JSONへ現れる。
- small finite domainでverified candidateをblockする。
- audit inconclusiveをsafe blockerへ昇格する。

いずれかが成立したblockerはsolverへ追加しない。
