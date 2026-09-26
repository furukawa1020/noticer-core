# Exact finite AQPP derivation

The quotient-profile-derive crate consumes K9 exact finite observable
distributions. For every declared public state and action-equivalent pair it
checks equal action semantics, detects support mismatch, computes both Renyi
moment directions with exact rational arithmetic, and takes the supremum.

Support mismatch returns an unbounded profile and is never replaced by a large
finite constant. Equal distributions derive moment one and log moment zero;
zero profiles cannot be asserted by callers.

The runtime conversion is deliberately conservative. It records an exact
rational moment and rounds the natural-log bound upward to a whole binary
magnitude in Q64.64. This coarse bound cannot underestimate the exact moment;
later tightness evaluation may replace it only with another directed upper
rounding implementation.
