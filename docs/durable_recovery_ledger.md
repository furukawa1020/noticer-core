# Durable recovery ledger

FileRecoveryLedger persists consumed recovery permit IDs in a single-writer,
append-only MAC chain bound to epoch and state generation. Startup verifies
the header, every sequence number, every chained tag, duplicate absence, and
record alignment before accepting state. Consume returns success only after
sync_data completes; ambiguous writes poison the live instance.

Corruption, partial records, wrong bindings, authentication failure, and lock
contention never fall back to an empty ledger or trigger repair. The chain
detects edits, reordering, and non-record-aligned truncation. Replacement by
an older complete and correctly authenticated prefix requires an external
trusted anchor and is not detected here. Hardware storage remains
NOT_VERIFIED.
