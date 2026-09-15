# K7 two-component bounded composition

Two buckets compose only when both AQNI and utility verdicts are VERIFIED and
their public handoff witness is COMPATIBLE. Horizon, query, retry, and failure
bounds are additive and are independently recomputed from both bound
contracts. Any non-verified source or boundary mismatch is fail-closed.

The output is a deterministic DERIVED_CANDIDATE and explicitly not a standalone
security proof. Concurrent composition, unbounded streams, and general privacy
accounting remain outside scope.
