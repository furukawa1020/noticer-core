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
