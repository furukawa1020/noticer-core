# Recovery Anti-Equivocation Ledger

The ledger assigns one authenticated checkpoint head to each monotonic recovery generation. Every record binds its predecessor. Re-observing the identical head is idempotent, a different head at the same generation is a fork, and an older generation is a rollback. Startup replays the complete bounded chain before accepting new observations.
