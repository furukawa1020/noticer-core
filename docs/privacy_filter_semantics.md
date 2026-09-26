# Pre-release AQPF filter semantics

`quotient-filter` is the fail-closed decision point between an accounted candidate and an externally observable release.

For every candidate prefix, the filter first asks AQPO for a time-uniform profile upper bound. It then applies a monotone policy in this order:

1. `allow`: emit the requested action semantics.
2. `delay`: retain the candidate without emitting it now.
3. `coarsen`: permit only a separately compiled, lower-information action.
4. `local-only`: consume the result only inside the trusted boundary.
5. `deny`: emit nothing derived from the candidate.

A coarsened action is not automatically authorized by this decision. It must be compiled and accounted as its own candidate before release. Any replay, rollback, budget-key mismatch, malformed profile, arithmetic overflow, or AQPO rejection maps to `deny` with no externally observable release.

The filter reports a profile-based upper bound. It does not claim to measure realized privacy loss.
