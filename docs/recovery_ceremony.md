# Recovery Ceremony Coordinator

The recovery ceremony is an authenticated, resumable state machine for startup security proofs.

1. Cross-store certification and rollback-anchor authorization are recorded together.
2. A startup admission permit is recorded only after security authorization.
3. The recovery witness batch is recorded only after admission authorization.
4. Release readiness is reached only after all prior phases are sealed.

Every checkpoint is HMAC-authenticated. Replaying an identical completed phase is idempotent, while phase skips, checkpoint tampering, and component substitution abort with a typed reason.
