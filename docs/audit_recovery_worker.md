# Audit Recovery Worker

`recover_delivered_audit` completes the durable transition from a `DELIVERED` outbox entry to `AUDITED` after process restart. It never contacts the delivery sink.

The worker reads the exact `SealedReceipt` from the durable vault, rechecks every public binding against the outbox intent, verifies and reconciles it with the receipt keyring and durable audit log, and only then synchronizes the outbox `AUDITED` transition.

If audit append succeeds but the final outbox sync fails, a retry discovers the existing audit record and finishes the outbox transition without appending a duplicate. A fully completed retry returns `AlreadyCompleted`. Missing, conflicting, or invalid state fails closed.

Recovery of `PENDING` delivery intents is deliberately excluded because it requires a separate sink reconciliation policy.
