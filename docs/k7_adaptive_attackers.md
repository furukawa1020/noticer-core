# K7 adaptive attacker registry

The registry freezes five observer capabilities: claim-only, full trace,
timing-size-failure, service collusion, and longitudinal observation. Each view
is attacked by four CPU models: standardized logistic regression, bounded-depth
decision tree, histogram gradient boosting, and a sequence-summary classifier.

The sequence classifier uses only the first pre-registered T observations and
derives mean, deviation, extrema, endpoints, and first-difference statistics.
The adaptive query budget limits the number of train/development examples
available to every attacker. Test labels never participate in fitting or model
selection.

Before fitting, the suite independently rejects pair, family, or session overlap
across train, development, and test. Outputs contain scores and predictions but
no pass/fail privacy interpretation. AUC, calibration, confidence intervals, and
excess leakage are assigned to K7-11d. Chance-level scores are not security
proofs.
