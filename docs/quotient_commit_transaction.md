# QuotientCommit Atomic Release Transaction

QuotientCommit is a candidate research mechanism that binds a checked release
certificate, an online action-equivalence verdict, an adaptive privacy profile,
a budget reservation, and one public trace commitment into one fail-closed
transaction. It does not establish a world-first claim.

The canonical transaction identifier is SHA-256 over the domain
`noticer.quotient-commit.transaction.v1\0`, the four binding digests, the
big-endian release sequence, and the big-endian policy epoch.

The only successful path is:

```text
PREPARED -> MONITOR_ACCEPTED -> BUDGET_RESERVED -> COMMITTED
```

`REJECTED` and `ABORTED` are terminal. `COMMITTED` is also terminal. A public
release permit is unavailable before `COMMITTED`. Every transition repeats the
transaction identifier and its relevant binding, preventing evidence from a
different release, certificate, relation, or privacy profile from being mixed
into the transaction.

This first core is intentionally in-memory. It does not yet claim durable crash
atomicity, distributed consensus, hardware enforcement, or physical validation.
Those properties require separate issues and evidence.

The crash journal extension records every accepted transition in a
domain-separated HMAC-SHA-256 chain. In-memory state advances only after
`append_and_sync` succeeds. Startup replay preserves an uncertain prepared or
reserved state without issuing a release permit, and rejects mutation,
reordering, replay, and any transition after a terminal record. The provided
memory store is a deterministic test adapter, not an OS durability claim.

The durable coordinator closes the call-order gap between the transaction and
the journal. It validates each transition on a copied candidate, synchronizes
the corresponding journal record, and only then replaces live state. A commit
permit is withheld until both state machines agree on `COMMITTED`. Binding
failure or store failure therefore cannot advance the externally visible
transaction state.
