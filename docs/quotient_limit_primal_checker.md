# QuotientLimit exact primal checker

The independent `quotient-limit-check` crate is `no_std` and has no solver
backend dependency. It accepts only canonical exact rationals and checks matrix
digest binding, dimensions, non-negativity, equalities, inequalities, and the
claimed objective. Arithmetic overflow and every resource-limit violation fail
closed.

A valid primal witness proves feasibility at its exact objective value. It does
not prove optimality; that requires the independent dual lower-bound path in
K9-QL-05.
