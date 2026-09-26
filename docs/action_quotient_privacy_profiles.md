# AQPP and AQPC format

AQPC version 1 is a fixed little-endian binary envelope. It binds the mechanism,
action quotient, secret family, observer coalition, public context, model
version, validity epoch, derivation source, checker contract, and an ordered
bidirectional AQ-RDP moment grid.

The certificate encoder and checker are separate production crates. The checker
parses bytes independently and returns exactly VALID_PROFILE, INVALID_PROFILE,
INCOMPATIBLE_PROFILE, UNBOUNDED_PROFILE, or RESOURCE_LIMIT. A dev-only
interoperability dependency generates test fixtures but is absent from the
checker runtime dependency graph.

Support mismatch is UNBOUNDED_PROFILE. Empirical derivations are rejected in
production and accepted only in explicit lab mode. Unknown flags, zero hashes,
noncanonical orders, truncation, trailing bytes, stale bindings, and oversized
order grids fail closed.
