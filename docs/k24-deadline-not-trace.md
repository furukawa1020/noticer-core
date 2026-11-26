# Deadline success is not trace equivalence

The success bit records whether a complete set of scheduled actions reached
its declared deadlines. It does not uniquely determine the ordered receipt
trace. In a two-slot tape with one flexible authorized action, sending the
action in slot 0 or slot 1 both succeed with probability 1. A decoded recipient
can distinguish the logical receipt slots.

The randomized solver does not consume private evidence, but it does not
establish how an upstream component selects authorized actions, how entropy is
shared, or how a decoded trace maps to wire traffic. No receipt-privacy, timing,
or AETP claim follows from the reported deadline value alone.
