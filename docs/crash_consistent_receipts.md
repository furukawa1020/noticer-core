# Crash-consistent privacy reservation and receipt

`quotient-crash-ledger` uses a write-ahead `prepare` record before an external release and a later `commit` record. A recovered `prepare` without `commit` is conservatively charged because the release may have occurred before the crash.

Every journal entry is a fixed 160-byte receipt. HMAC-SHA256 authenticates its semantic fields, and each receipt includes the previous authenticator to form a tamper-evident chain. Recovery verifies authentication, chain order, sequence continuity, reservation uniqueness, and exact prepare/commit agreement before rebuilding state.

`append_and_sync` is the durability boundary. In-memory state changes only after that call succeeds. The supplied memory store is a deterministic test adapter; production deployments must provide storage whose successful sync survives their stated crash model.

The HMAC is symmetric authentication, not a publicly verifiable digital signature. Key custody and durable anti-rollback storage remain deployment responsibilities.
