# Startup Recovery Orchestrator

`run_startup_recovery` provides a deterministic and bounded startup pass over authenticated outbox state. Entries are processed in transaction identifier order.

`PENDING` entries are routed only to pending-delivery recovery. `DELIVERED` entries are routed only to audit recovery. `AUDITED` entries are reported as completed without invoking either recovery path. This separation prevents a delivery sink from being contacted for an already delivered transaction.

Each transaction produces an independent result. A failure is retained in that result and does not prevent later entries in the same batch from being attempted. A positive batch limit is mandatory so startup work remains bounded.

The executor interface is intentionally narrow. Production composition supplies the transaction-specific coordinator, sink, keyring, vault, and audit resources used by the existing recovery workers.
