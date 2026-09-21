# Runtime generation guard

GenerationGuardedClock holds the authenticated clock, monotonic anchor,
durable recovery-ledger lock, and external generation anchor for the full
runtime lifetime. Startup verifies the complete StateSnapshot commitment
before SoftwareCore is constructed.

Each public-slot advance updates the authenticated clock and monotonic anchor,
then compare-and-advances the generation commitment. Any failure poisons the
guard and SoftwareCore returns DurableClock before token verification or
action execution. No weaker clock backend is selected automatically.

The recovery ledger cannot be opened concurrently while the runtime guard is
active. Hardware anchors, provisioning, and crash recovery remain
NOT_VERIFIED.
