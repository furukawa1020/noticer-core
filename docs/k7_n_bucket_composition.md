# K7 N-bucket composition oracle

The independent oracle checks a non-empty ordered bucket sequence. Each bucket
binds one source certificate and one finite resource budget. Interior buckets
must provide both incoming and outgoing public handoffs; these endpoints must
bind the same source and bounds as the bucket.

The oracle checks every adjacent compatibility relation, preserves witness
order, and adds each bucket budget exactly once. N=1 is the base case, N=2 is
one induction step, and larger N repeats the same checked rule. Reordering,
missing interior endpoints, substitutions, and non-verified verdicts fail
closed.

Acceptance is bounded independent-oracle evidence, not a proof for unbounded or
concurrent composition.
