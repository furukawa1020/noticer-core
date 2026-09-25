# Exact and approximate AETP

QuotientLimit keeps Exact, Total Variation, and rational rho-delta as distinct
privacy modes. Distributions are canonical exact rational vectors. TV is half
the L1 distance; rho-delta checks directed hockey-stick divergence in both
directions. Epsilon is report-only and never enters a certificate as a float.

For equal-prior binary inference the exact Bayes success is `(1 + TV) / 2`.
A weak empirical classifier is therefore not evidence that privacy holds.
