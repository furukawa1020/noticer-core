# An exact two-history receipt/utility boundary

The two private histories fix the same authorization, deadlines, capacity,
and action-to-recipient mapping. They can differ in which slots are privately
available for each action. A trusted planner knows the chosen history at
planning time and can withhold actions. There is no online unknown future
in this model. The observer reads decoded logical receipt events of a fixed
recipient subset, optionally including a public failure indicator.

For two unconditional trace distributions, allocate their pointwise overlap
to matched traces. Its total mass is one minus total variation. Remaining
mass is unmatched. For an exact match, a trace may admit complete plans in
both worlds, one world, or neither. A shared complete trace gives value one.
If both directions of exclusive success are available, mix two matched pairs
equally to attain one half; the per-pair summed success is at most one.
Otherwise a world has no matched complete plan, and the worst value is zero.

If each world can independently succeed and the TV allowance is delta,
assign up to delta mass to independent complete plans and use the exact
matching strategy for the rest. This attains v0 + delta * (1 - v0).
The overlap decomposition gives the same upper bound, since an unmatched
component gives at most one and the matched component is limited by the
exact value v0. If a world is individually unreachable, every bound is zero.
The checker recomputes reachable traces by separate Cartesian enumeration.

At most two histories, five scheduled actions, and five slots are modeled.
Each world has at most 6^5 complete-or-partial action assignments before
capacity filtering. Unknown receiver names and malformed schedules are not
infeasibility witnesses. An exhausted search or checker budget is inconclusive.
No network acknowledgments, real time, physiological data, auditing device
traces, online availability, or privacy across additional histories is certified.
