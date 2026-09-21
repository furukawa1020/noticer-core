# Durable recovery integration

recover_clock_with_durable_ledger requires an authenticated FileRecoveryLedger
before entering the signed recovery ceremony. Ledger corruption, binding
failure, or lock contention aborts recovery and never selects an in-memory
fallback.

The integration test completes recovery, rolls only the clock and anchor back
to their prior values, restarts the ledger, and confirms that the consumed
permit is still rejected. A coordinated rollback of clock, anchor, and ledger
to one older valid snapshot still requires a trust anchor outside these files.
Hardware-backed rollback protection remains NOT_VERIFIED.
