# ATv2 verifier semantics

## Public API

The verifier exposes only three outcomes:

```text
Cover
Authorized { action, token_id }
Rejected
```

Detailed internal failure classes are not returned. This reduces differences
that could become a verification oracle.

## Fail-closed order

1. Require an exact 236-byte canonical envelope.
2. Bind the public epoch and locate the pairwise service key.
3. Match the verifier's expected service and epoch.
4. Recompute and compare the deterministic nonce.
5. Authenticate and decrypt with the outer header as AAD.
6. Verify Ed25519 over the outer header and inner body.
7. Parse the canonical body and reject revoked keys.
8. For cover, return `Cover` without privileged action.
9. For action, check validity window and policy revocation.
10. Enforce minimum claim, local claim ceiling, action/policy binding, and the
    allowlisted action-semantics tag.
11. Atomically consume `(epoch, token_id)` in the replay store.
12. Return only the authorized action and opaque token ID.

Replay is checked last so an unauthenticated attacker cannot fill the replay
store. The in-memory implementation performs one atomic set insertion under a
mutex; the concurrency test requires exactly one acceptance from 64 threads.

## Persistent replay state

`InMemoryReplayStore` exports a versioned JSON snapshot containing only epoch
and used token IDs. Import rejects malformed JSON, a schema mismatch, an epoch
mismatch, and duplicate IDs. Production deployments should place equivalent
atomic semantics behind durable, rollback-protected storage. Snapshot export
does not include keys, policy bodies, or private evidence fields.

## Revocation

The verifier accepts immutable `RevocationSnapshot` data for key IDs and policy
hashes. Revocation freshness and distribution are deployment responsibilities.
Failing to refresh a snapshot is an operational risk rather than a change to
the token's cryptographic validity.
