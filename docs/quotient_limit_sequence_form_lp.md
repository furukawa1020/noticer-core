# QuotientLimit sequence-form LP

`quotient-limit-sequence-lp` represents a causal behavioral strategy with
`reach[i]` and `flow[i,a]`. One policy row per public information set prevents
private-history-specific branching. Root mass, exact public transition
probabilities, and incoming flow conservation are explicit equality rows.

Terminal observation contributions generate exact AETP rows only between
histories in the same action quotient class. Coefficients are reduced rational
numbers; floating solver residuals are not accepted as semantics. The matrix is
bound to `QUOTIENT_LIMIT_SEQUENCE_MATRIX_V1` for later certificate checking.
