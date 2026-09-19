# Authenticated durable public clock

The opt-in authenticated record binds format, epoch, state generation, and slot with HMAC-SHA-256. Authentication is checked before adopting a slot. Unknown formats, malformed records, tag failure, binding mismatch, rollback, lock contention, and write ambiguity fail closed. There is no plaintext migration or wall-clock fallback.

A tag detects modification but not replacement by an older valid record. That requires an external trusted monotonic anchor. Hardware key storage and counters remain NOT_VERIFIED. No world-first claim is made.
