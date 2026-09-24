# QuotientLimit dual lower-bound checker

The independent checker reconstructs each dual lower bound with exact rational
arithmetic. Equality multipliers are unrestricted, while multipliers for primal
`<=` rows must be non-positive. Every reduced-cost inequality and the claimed
bound are recomputed without trusting a solver status or floating residual.

Certified optimality additionally requires an independently valid primal
witness, exact equality of primal and dual values, and complementary slackness
for every variable and inequality row.
