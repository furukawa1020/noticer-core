# Recovery Witness Startup Worker

The startup worker binds each deterministic recovery decision to an authenticated, privacy-safe witness chain.

- `PENDING`, `DELIVERED`, and `AUDITED` map to retry-delivery, retry-audit, and no-op witnesses.
- The public binding is domain-separated and derived from public trace metadata; transaction and subject identifiers are excluded.
- A failed item becomes `FailedClosed` without preventing later entries from being processed.
- The complete batch is handed to a durability sink only after its witness chain has been built.

The sink is an explicit trust boundary. A sink failure rejects the worker result even though external recovery actions may already have occurred; callers must retry from the durable outbox and rely on idempotent executors.
