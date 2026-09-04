# QBF model acceptance boundary

K7-05dは、QBF solverの`SAT`をAQRS candidateの受理と同一視しないための境界を固定する。

## Acceptance pipeline

1. solver result、QDIMACS、semantics metadataのdigest、seed、boundsを相互照合する。
2. `V ... 0` assignment行だけをparseし、範囲外、重複、矛盾、欠落を拒否する。
3. QDIMACS registryで`MACHINE_CHOICE`とされたouter existential変数だけを読む。
4. exactly-oneのcandidate IDをsemantics metadataへ解決する。
5. cell totality、座標range、重複、first-use canonicality、candidate SHA-256を再検査する。
6. candidateを`SynthesisProblem::lower_candidate`でchecker modelへ変換する。
7. solverおよびQBF encoderから独立した`quotient_forge_check::check`を実行する。
8. checkerが`Verified`を返した場合だけ、`candidate_accepted=true`とcandidate machineを返す。

universal trace変数とdependent witness変数はassignmentに含まれていてもcandidate構成には使用しない。partial model、false SAT、checker resource exhaustionは受理しない。

## Decision taxonomy

- `ACCEPTED`: SAT、完全なmachine assignment、valid candidate、独立checkerの`VERIFIED`がすべて成立
- `REJECTED`: contract、parse、decode、hash、checkerのいずれかが拒否
- `INCONCLUSIVE`: 独立checkerがnode、depth、time limitで完了しなかった
- `NOT_APPLICABLE`: solver結果がSATではない

`UNSAT_AT_BOUND`はglobal unrealizableを意味しない。`INCONCLUSIVE`も安全性の成立を意味しない。

## Canonical artifact

schemaは`noticer.quotient_forge.qbf_candidate_decision.v1`である。artifactは次を結合する。

- QDIMACS、semantics、stdout、canonical assignment、decoded candidateのSHA-256
- solver resultとfinal decision
- checker limits、status、探索量、到達深度
- machine IDとchecker rejection diagnostic
- 常にtrueの`bounded_only`

accepted artifactは、SAT、candidate ID/hash、assignment hash、checker `VERIFIED`、diagnosticなしを同時に満たさなければserializeできない。

## Non-claims

- solver modelの完全性は主張しない。
- SAT assignment単体をsecurity proofとして扱わない。
- bounded verificationをunbounded保証へ昇格しない。
- universal assignmentやdependent witnessをmachine implementationへ変換しない。
