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


## Crash intent journal

The strongest software constructor requires a separately keyed, authenticated generation transition journal. Every advancing slot follows Prepared -> durable clock and monotonic anchor -> generation commitment -> Committed -> Clean. Startup accepts only Clean; an authenticated unfinished transition fails closed before runtime construction. Reconciliation is intentionally deferred to an explicit recovery ceremony. Hardware-backed atomicity and power-loss behavior remain NOT_VERIFIED.
