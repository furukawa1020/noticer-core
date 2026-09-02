# QuotientSeal Evidence Completeness and Secret Audit v1

## 目的

evidence auditは、replication packageの必須artifact、digest、verdict集計、非成功結果ledger、private/secret非混入を固定taxonomyで機械確認する。これは限定的な構造・pattern監査であり、全情報漏えいの不存在証明やsecurity verdictではない。

## Required evidence

indexは次の14種を最低1件ずつ持つ。

1. MANIFEST
2. REPRODUCTION_REPORT
3. CAPSULE
4. CERTIFICATE
5. RELATION
6. CONTEXT
7. COUNTEREXAMPLE
8. MUTATION_REPORT
9. ENGINE_REPORT
10. ATTACK_REPORT
11. PERFORMANCE_REPORT
12. ABLATION_REPORT
13. STUDIO_EXPORT
14. INVARIANT_REPORT

各recordはID、kind、POSIX relative path、content type、verdict、reason code、byte length、raw file SHA-256を持つ。manifestとreproduction reportはファイル内部のartifact digestもindex上流digestと一致しなければならない。

## Non-pass ledger

次を件数0の場合も明示する。

- ESCAPED_MUTANT
- ENGINE_DISAGREEMENT
- RESOURCE_BOUND
- UNSUPPORTED

件数が1以上の場合、ledgerは同じreason codeを持つ非PASS recordを全件参照する。PASS recordへの参照、件数不一致、未知ID、code欠落はFAILとする。record全体のPASS / FAIL / INCONCLUSIVE / NOT_RUN集計も再計算する。

## Path and size boundary

- absolute path、backslash、`.`、`..`、symlink、package外解決を拒否する。
- indexは2 MiB、recordは512件、1 artifactは128 MiB、合計1 GiBを上限とする。
- JSONはdepth 32、node 100,000を上限とする。
- `.pem`、`.key`、`.p12`、`.pfx`、`.env`、`.credentials`を拒否する。

## Private and secret taxonomy

JSON keyではraw biosignal sample、personal baseline、subject/participant/device stable ID、secret/private/API key、password、credentialを拒否する。text/binaryのUTF-8 projectionではPEM private key、AWS access key、GitHub token、Bearer token、generic secret assignmentの固定patternを検査する。

検出reportはsecret値を引用せず、固定messageとrecord ID/pathだけを残す。

## Verdict

- structural、digest、completeness、ledger、secret違反がなければPASS
- いずれかの違反があればFAIL
- 将来WARNING taxonomyを追加した場合、ERRORなし・WARNINGありはINCONCLUSIVE

parse failure、unknown field、scan bound超過をPASSにしない。

## Outputs

JSONはcanonical UTF-8、Markdownは同じreportから決定的に生成する。両方ともraw evidence値を掲載しない。出力は`artifacts/replication/audit/`配下に生成しGitへcommitしない。

## Claim boundary

- `audit_scope = BOUNDED_PATTERN_AND_STRUCTURAL_AUDIT`
- `evidence_origin = SOFTWARE_AUDIT`
- `security_interpretation = NOT_A_SECURITY_VERDICT`
- `hardware_status = NOT_VERIFIED`
- Polar Verity Sense実機、実biosignal、priority claimは検証しない。

