# K7 adaptive leaky controls

The leaky control is a deliberately invalid trace representation that exposes
the private-side label in every observer view. It is generated only as a wrapper
around a protected dataset and preserves labels, pair IDs, family IDs, session
IDs, and split indices. It therefore tests attacker sensitivity without changing
the evaluation population.

Control artifacts use the controls/k7_adaptive namespace and carry the protected
dataset digest. They are never runtime evidence and cannot be mixed into the
protected artifact directory.

All twenty pre-registered observer/model combinations must reach the frozen
minimum AUC. One blind or failed attacker invalidates the evaluation rather than
making the protected result look safer. Passing this control establishes only
that the attack harness detects an explicit leak; it is not evidence of privacy.
