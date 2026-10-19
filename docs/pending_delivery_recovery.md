# Pending Delivery Recovery

`recover_pending_delivery` resolves the crash interval after a `PENDING` outbox record is durable but before a `DELIVERED` transition is durable.

The worker requires a recovered committed descriptor, an idempotent sink, an active receipt epoch, the durable outbox, and the sealed receipt vault. Every public binding is checked before the sink can be contacted.

For a new recovery attempt, the worker reconciles with the sink, seals the public receipt, synchronizes it into the vault, and only then synchronizes the outbox `DELIVERED` transition. If the final transition fails, the next attempt uses the vaulted receipt and does not contact the sink again.

The guarantee depends on the sink durably deduplicating transaction identifiers and rejecting conflicting public bindings. Non-idempotent sinks are outside this boundary.
