# Finite public game certificates

An input has up to eight fixed public availability tapes, eight logical
slots, and eight unit actions. All tapes agree on deadlines, horizon, and the
first public observation. At each slot a schedule sees only the prefix of
capacity and eligible action sets. It does not get the tape ID or private data.

A strategy selects one legal subset at each observed prefix. A decision is
winning exactly when any action left unsent still has time and every reachable
next public observation admits a winning decision. An empty remainder ends
the run successfully. The search implements this recursion with a fixed move
budget. A budget exhaustion carries no certificate.

The policy checker replays every tape rather than trusting the search's
information-set construction. The loss checker reconstructs every legal subset
and for each such decision checks an immediate miss or a reachable successor
that is itself losing. Induction backwards from a deadline proves the finite
result. Neither checker asserts safety beyond the declared tapes.

A separate differential oracle enumerates all pairs of complete allocations
on 272 small tape pairs and checks that each candidate pair uses identical
decisions up to the first different public observation. This cross-check
targets the two-tape contract; it is not empirical evidence and not a general
proof of the implementation for unbounded inputs.
