# What the exact mixed policy adds

A finite, public-history release game now returns a pair of evidence: a
distribution over feasible causal decisions and an independently checked upper
bound on the best worst-tape success. Legal choices after visible branches
can differ, but a choice never depends on the realized hidden tape identifier.
The verifier can replay a versioned portable bundle without synthesis.

## Why the pair is sufficient

For the lower bound, replay each deterministic policy on every admitted tape
and sum the exact probability mass that succeeds on that tape; take the
minimum. For the upper bound, take the proposed tape distribution and
independently maximize weighted success by dynamic programming over public
histories. Any policy mixture's worst tape cannot exceed its average under
that distribution, and linearity bounds that average by the best deterministic
weighted policy. Equal bounds certify optimality under the declared order of
information. No correctness of simplex or frontier pruning is required by
that verification argument.

## Research decision

Keep the result as a small certifying scheduler with a useful no-conjecture
story. Do not present it as a new minimax theorem, proof of AETP, real-network
privacy evidence, or a large improvement over a strong heuristic. In the
complete two-slot grid the strong comparator often ties. A future paper needs
a source of public uncertainty classes from an actual owned deployment,
multi-step behavior under realistic deadlines, and a separate receiver-trace
privacy evaluation. A verifier hash identifies the artifact's bytes; it is
not a signature or an authorization to make claims about the source.
