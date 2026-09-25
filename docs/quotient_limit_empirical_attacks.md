# QuotientLimit Empirical Attack Validation

K9-QL-13 keeps empirical attacks independent from certificate checking. The authoritative equal-prior finite-distribution attacker computes total variation and Bayes success `0.5 * (1 + TV)` from exact mechanism distributions.

Logistic regression, random forest, extra trees, and histogram gradient boosting are reported as empirical baselines on strictly session-disjoint partitions. Weak ML performance is never treated as evidence of privacy; the formal finite-distribution bound remains authoritative.

Sampler validation reports empirical frequencies, exact probabilities, per-cell 95% normal intervals, Pearson goodness-of-fit statistic, degrees of freedom, and maximum absolute error. Formal and empirical TV are compared under an explicit tolerance.
