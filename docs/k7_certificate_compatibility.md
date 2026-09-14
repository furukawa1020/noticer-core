# K7 certificate compatibility

Adjacent bounded-AQNI certificates compose only when their closed public
handoff contracts agree on action semantics, observer contract and state,
service-collusion membership, epoch, and key epoch. The left public epoch event
must be at its certified horizon; the right event must be at slot zero.

Every decision binds both complete contract digests. A certificate digest
substitution therefore changes the witness even when the public boundary
remains compatible. Mismatches are sorted stable reason codes.

COMPATIBLE is a compatibility witness, not a security proof and not a
composition theorem. It does not validate either source certificate.
