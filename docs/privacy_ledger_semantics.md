# Concurrent multi-service privacy ledger

`quotient-ledger` provides the linearization point for concurrent privacy-budget reservations.

A release path must reserve its upper-bound cost before any external effect, then either commit that exact reservation or abort it. Capacity checking and reservation insertion happen while holding the same mutex. Therefore concurrent services cannot both observe stale capacity and overspend it.

Reservation identifiers are single-use, including after abort. A service cannot commit or abort another service's reservation. Duplicate commits, arithmetic overflow, resource exhaustion, unknown identifiers, ownership mismatch, and poisoned synchronization state all fail closed.

Committed spend is not refundable. Aborting only releases pending capacity. The ledger is an in-memory state machine; durable crash recovery and signed receipts are handled by the subsequent crash-consistency task.
