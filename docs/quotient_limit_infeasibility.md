# QuotientLimit infeasibility certificates

The independent checker accepts a Farkas witness only when exact arithmetic
shows non-positive inequality multipliers, non-positive combined coefficients
for every non-negative primal variable, and a strictly positive contradiction
bound. Solver `INFEASIBLE`, timeout, and exhausted search are not certificates.

The explanation reports the stable labels supporting the accepted witness.
It deliberately marks minimality as `NotEstablished`; support extraction is not
misreported as an irreducible or minimum conflicting core.
