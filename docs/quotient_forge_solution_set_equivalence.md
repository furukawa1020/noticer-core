# QuotientForge small-model solution-set equivalence

K7-07e provides bounded experimental evidence that quotient reduction preserves the valid policy set. It is deliberately a small-model exhaustive check, not a proof for arbitrary bounds.

## Frozen domain

The caller fixes the seed, control-state count, symbol count, output count, and a hard candidate limit. The canonical quotient fixes the original-state and quotient-class counts. Both spaces are rejected before enumeration if their complete Cartesian product cannot be visited within the fixed limits.

The unreduced space contains total tables indexed by `control_state x source_state x symbol`. The reduced space contains total tables indexed by `control_state x quotient_class x symbol`. Every cell ranges over the same `next_control_state x output` choices.

## Two independently checked sets

Every unreduced candidate is submitted to `check_unreduced`. Every reduced candidate is submitted to `check_reduced`, passed through the validated K7-07d lift, and checked again as an unreduced candidate. A reduced/lifted checker disagreement prevents `PASS` even when the final digest sets happen to match.

Valid policies are normalized over source ordinals and all control-state renamings that preserve initial state zero. Their minimum canonical serialization is hashed and inserted into a sorted set. The comparison therefore ignores source identifiers, enumeration order, duplicates caused by state naming, and the quotient representation itself.

## Outcomes and witnesses

- `PASS`: both complete canonical sets match, no checker is inconclusive, and reduced/lifted decisions agree.
- `FAIL`: at least one missing or spurious canonical solution exists, or the reduced and lifted checker decisions disagree.
- `INCONCLUSIVE`: any checker call is inconclusive. This takes priority over apparent set equality.

The artifact records the complete sorted digest sets plus separate first witnesses for missing and spurious solutions. It binds the source problem, quotient, preservation result, lift mapping commitment, frozen domain, candidate counts, checker-call counts, and outcome in a canonical digest.

Private history labels and raw source indexes are not serialized. The evidence only applies to the exact finite domain recorded by the artifact.
