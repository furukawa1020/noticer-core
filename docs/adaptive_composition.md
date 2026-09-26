# Conditional adaptive AQ-RDP composition

The quotient-accountant-core crate composes only profiles selected before a
release from public transcript, public budget, utility, and network state.
Every step must retain one exact BudgetKey: secret family, observer coalition,
action quotient, secret model version, and policy epoch.

The alpha grid is canonical and immutable. Directed upper log moments add with
checked arithmetic. Exact AETP zero profiles add zero cost. A failed step never
partially mutates accountant state.

Composition fails closed on hidden-state selection, late profile choice, stale
profile epoch, coalition expansion, invalid profile, transcript replay, release
sequence discontinuity, alpha-grid mismatch, binding mismatch, and arithmetic
overflow. These checks encode the conditions under which adaptive conditional
composition is claimed; they do not establish those conditions for undeclared
observers or secret families.
