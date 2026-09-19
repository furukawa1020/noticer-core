# Durable public clock watermark

DurablePublicClock stores one epoch-bound public slot watermark for the
software runtime. Every forward transition is written and synchronized before
it is accepted. Restart with an older slot, a different epoch, a partial or
altered record, or an unavailable writer lock fails closed.

The caller supplies trusted public slots. The clock does not infer time from a
biosignal, private evidence timing, or the host wall clock. It does not repair
files or automatically remove stale locks. Ledger files and locks must remain
in trusted, access-controlled local storage and are not release artifacts.

The complement field detects incomplete writes; it is not cryptographic
integrity. Hardware secure-clock behavior, hostile disk modification, and
power-loss guarantees on a target device remain NOT_VERIFIED.
