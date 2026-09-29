# Coalition-aware privacy accounting

`quotient-coalition` binds every declared observer coalition to one joint privacy budget. All services assigned to that coalition consume the same counter, so splitting one release strategy across additional service identifiers does not create additional budget.

Observer lists are canonical, strictly ordered, and declared before service registration. This implementation uses disjoint declarations: an observer cannot silently participate in two tracked coalitions. Unregistered services and services claiming a different coalition fail closed.

Charge identifiers are globally single-use within the accountant. Every accepted charge binds the service, coalition, amount, and release-trace commitment in its receipt. Capacity checks and updates share one mutex linearization point.

This primitive enforces declared-coalition accounting. It does not discover undeclared real-world collusion; deployment policy must conservatively declare every observer set that can share release traces.
