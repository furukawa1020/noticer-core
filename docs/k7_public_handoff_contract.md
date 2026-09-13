# K7 public-only handoff contract

The noticer.k7.public-handoff.v1 format fixes the only state allowed to cross
a bounded AQNI bucket boundary: the complete observer-state digest, sorted
service-collusion set, public epoch/key-epoch event, finite resource bounds,
and digests for action semantics, observer contract, and source certificate.

There is no generic metadata map. Unknown fields are rejected. Private cache,
private history, raw biosignal, and secret retry carryover receive the stable
forbidden_private_carryover category. Epoch and key changes are public events,
not implicit secret transitions.

This structural contract cannot prove that an untrusted producer did not
encode private data inside a nominally public identifier or digest. Producers
remain in the TCB until translation validation binds fields to declared
observer semantics.

This is a prerequisite for a proposed bounded composition theorem, not the
theorem itself. It does not claim arbitrary concurrent composition, unbounded
stream privacy, deployment privacy, or general Pufferfish/DP accounting.
