# QuotientLimit explicit trace LP

`quotient-limit-trace-lp` is the solver-independent small-model semantics oracle.
It creates one non-negative variable `p[h,y]` for every private history and
utility-feasible complete trace. Unauthorized, duplicate, too-early, and
post-deadline actions never become LP variables.

Every history receives a probability-normalization equality. Every pair of
histories in one action quotient class receives an equality for each declared
observer and observation. Thus the action quotient materially determines
`A_priv x = 0`; this is not a generic scheduling wrapper.

The sparse matrix uses integer coefficients and a
`QUOTIENT_LIMIT_MATRIX_V1` digest. Trace enumeration is exponential in the
horizon, so this crate is a reference oracle for small models and future
sequence-form cross-checks, not the scalable formulation.
