# QuotientForge reduced candidate lift

K7-07d fixes the translation boundary between a quotient-indexed synthesis result and the policy over original source states. It does not claim that quotienting itself is sound; a valid K7-07b preservation artifact is a mandatory input.

## Contract

The reduced candidate is a deterministic total Mealy table indexed by `control_state x quotient_class x symbol`. Missing, duplicate, out-of-range, or non-canonical cells fail before translation.

The process-local lift mapping binds each original source state to exactly one canonical quotient class. Translation proceeds only when the mapping:

- belongs to the current problem and quotient artifact;
- covers every original state exactly once;
- assigns every state to the class recorded by the canonical partition;
- reaches every quotient class; and
- matches its canonical commitment.

The lifted table duplicates each quotient-class cell for every source state in that class. Source indexes remain process-local. The public artifact records counts and a normalized lifted-candidate digest, but sets `source_indices_included` to `false`.

## Independent validation gate

Translation is not acceptance. The fully lifted candidate is submitted exactly once to an independent `LiftedCandidateChecker`. Only `valid` sets `accepted` to `true`; both `invalid` and `inconclusive` fail closed. Invalid or stale inputs are rejected before the checker call.

The checker remains an explicit trust boundary. This artifact is evidence that translation inputs were bound and a checker decision was recorded, not a proof certificate.

## Digest chain

`noticer.quotient_forge.quotient_lift.v1` binds:

- source problem digest;
- canonical quotient artifact digest;
- preservation artifact digest;
- normalized lift-mapping commitment;
- reduced candidate digest; and
- source-label-independent lifted candidate digest.

Any change to an upstream problem, partition, preservation result, mapping, or candidate therefore produces a different artifact or a fail-closed validation error.
