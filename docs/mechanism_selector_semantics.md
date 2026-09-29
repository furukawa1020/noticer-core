# Budget-aware certified mechanism selection

`quotient-selector` selects only from certified mechanisms using public context, profile commitment, remaining budget, and public utility rank. Ties are deterministic.

Each decision is immutable and single-use by identifier. Release authorization rechecks the selected mechanism, public context, and profile. A changed public context requires reselection. A mechanism mutation or any mutation attributed to private evidence fails closed.

This API intentionally accepts no private biosignal or private evidence as selection input. It does not certify the mechanism itself; only certificates established by the surrounding verification pipeline may be registered.
