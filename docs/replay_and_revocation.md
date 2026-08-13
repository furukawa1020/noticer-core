# Replay and revocation operations

## Replay invariant

An authenticated ATv2 action has `max_uses = 1`. Authorization therefore
requires an atomic first-use decision for `(public_epoch, token_id)`. A
check-then-insert sequence outside one transaction is invalid because concurrent
verifiers could both authorize the action.

The reference store uses a mutex-protected ordered set. Production adapters must
provide equivalent linearizable semantics, for example a unique database key in
a transaction or a hardware-backed monotonic store.

## Restart procedure

1. Stop authorization or enter fail-closed mode.
2. Load the last authenticated replay snapshot for the active epoch.
3. Reject schema mismatch, epoch mismatch, malformed input, or duplicate IDs.
4. Restore the atomic replay store before accepting network traffic.
5. Rotate epoch keys if rollback cannot be ruled out.

The reference JSON snapshot is a portability mechanism, not an authenticated
storage container. Deployments must authenticate it and prevent rollback.

## Revocation model

Key IDs and policy hashes can be revoked independently. A verifier checks key
revocation after successful authentication and policy revocation before replay
consumption. Revocation snapshots should be signed, versioned, monotonic, and
refreshed according to the deployment's risk window.

Emergency response should rotate the epoch, distribute new pairwise verifier
keys, revoke the old key ID, and retain old replay records until all old tokens
are outside their validity windows.

## Failure behavior

Storage lock failure, snapshot corruption, unknown key, stale epoch, and replay
all fail closed. External callers receive the same `Rejected` value rather than
an internal diagnostic category.
