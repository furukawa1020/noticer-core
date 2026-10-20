# Deterministic Crash-Point Matrix

`CrashCampaign` enumerates seven durability boundaries in the vaulted delivery protocol: before `PENDING`, after `PENDING`, after the sink effect, after vault synchronization, after `DELIVERED`, after audit synchronization, and after `AUDITED`.

Every schedule restarts from the durable state visible at that boundary and applies the same recovery rules used by the live protocol. The resulting witness records sink effect count, audit record count, terminal state, convergence, and fail-closed status.

The normal campaign requires at-most-one external effect, at-most-one audit record, and convergence to either no durable intent or `AUDITED`. The substitution campaign injects a conflicting public binding at every boundary and requires rejection without any additional effect.

`canonical_json` emits the matrix in a stable order without timestamps or randomness. It is suitable for CI artifacts and exact replay comparisons; generated output is not committed to Git.
