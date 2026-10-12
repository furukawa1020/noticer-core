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

Recovery requires the original public transition evidence and checks each item
against its authenticated journal digest before rebuilding state. A normal
commit exposes its permit through a one-shot take operation. Recovery of an
already committed transaction deliberately exposes no permit because the
system cannot distinguish a crash before delivery from a crash after delivery.
This fail-closed rule prevents automatic duplicate release at the cost of
possible lost utility.

The cross-platform file adapter serializes each journal entry as a versioned
144-byte record, holds a create-new single-writer lock, and calls `sync_data`
after every complete append. Reopening rejects truncated tails, malformed
headers, unknown record kinds, oversized files, and authenticated payload
mutation. It does not claim that every filesystem or storage controller honors
the same durability semantics, and it does not silently repair corruption.

## Idempotent release delivery ceremony

QuotientCommit separates durable `COMMITTED` state from delivery to an
external sink. A live coordinator exposes one one-shot permit through
`deliver_once`. If the sink applies the effect but its acknowledgement is
lost, the caller must recover the coordinator from the authenticated journal
and call `reconcile_committed`.

The sink contract uses the transaction ID as an idempotency key. It must
durably return `Delivered` for the first identical binding,
`AlreadyDelivered` for a duplicate identical binding, and `BindingConflict`
when the same ID is presented with different public semantics. This gives an
exactly-once effect only conditionally on that sink contract. QuotientCommit
does not claim generic exactly-once network delivery, actuator execution, or
hardware persistence.

The recovery API never returns a reusable permit. It passes the committed
descriptor directly into the idempotent sink ceremony, preserving the
one-shot boundary for ordinary callers. A delivery receipt reports the public
transaction binding and the sink's answer; it is not independent proof that a
dishonest or non-durable sink honored the contract.

`FileSink` is a local-filesystem reference implementation of that contract. It
stores versioned fixed-size public permit bindings, synchronizes each new
record before reporting `Delivered`, and rebuilds its deduplication index on
restart. A create-new lock limits the reference adapter to one writer. It
rejects conflicting duplicate IDs, malformed or truncated records, and size
limit violations rather than repairing them. These properties do not extend
to distributed hosts, network filesystems, storage controllers that violate
sync semantics, or physical actuators.

Delivery receipts can be sealed with a domain-separated HMAC-SHA-256 over the
transaction ID, public trace digest, release sequence, policy epoch, sink
outcome, and sink epoch. Verification detects mutation and cross-transaction
substitution while keeping the receipt free of private evidence. The MAC is a
symmetric integrity mechanism: it does not prove to a third party that the
sink performed an effect, and it does not replace remote attestation or a
hardware root of trust.

Sealed receipts can be ordered in a keyed append-only receipt log. Each record
authenticates its log sequence, predecessor authenticator, and sealed receipt,
so full replay rejects mutation, reordering, middle deletion, wrong keys, and
cross-log substitution. A separately retained count/head checkpoint detects
tail truncation. Without that external checkpoint, a valid prefix remains a
valid prefix; this layer does not provide trusted timestamps, transparency
publication, or durable storage by itself.

`ReceiptFile` is the local-filesystem reference store for that chain. It uses
versioned 208-byte records, a create-new single-writer lock, bounded file size,
and `sync_data` after each complete append. Restart loading preserves every
field needed for full keyed replay and rejects malformed or truncated data.
Its durability claim remains conditional on local filesystem sync semantics.

`ReceiptKeyring` makes receipt key rotation explicit. New receipts use only a
selected active epoch, while registered historical epochs remain available for
verification. Epoch identifiers and keys cannot be zero or overwritten, and
unknown epochs fail closed. The in-memory reference keyring does not provide
key distribution, revocation policy, KMS integration, or HSM protection.
