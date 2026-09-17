# K7 shared baseline comparison contract

All seven mechanisms receive one identical finite case, observer, action
utility/deadline, fault trace, cost contract, and corpus. Their six digests
are bound once in the shared manifest, not independently chosen per baseline.
Parameter selection is restricted to the development split and a
precommitted candidate set; evaluation uses held-out cases.

Every mechanism records whether it is an original implementation, an
approximation, or local code, along with source reference, version, and
privacy notion. Pacer-like, NetShaper-like, and automata entries cannot be
silently labeled local. This contract does not assert that a later
approximation faithfully reproduces a published system.

Attack, bandwidth, failure, latency, and state remain separate report axes.
AQNI exact equality, secret-independent cadence, DP, and automata privacy
must not be collapsed into one privacy score. A comparison is not a security
proof and does not establish a universal ranking.
