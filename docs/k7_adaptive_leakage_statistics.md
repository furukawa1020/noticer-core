# K7 adaptive leakage statistics

Each of the twenty pre-registered attackers is evaluated with ROC AUC, attacker
advantage, Brier score, expected calibration error, and a 95 percent interval.
Intervals resample complete matched pairs rather than individual rows. The same
resampled pairs are used for claim-only and full-trace scores of a model, making
their excess leakage contrast paired.

Full-trace excess is reported separately for linear, tree, boosting, and
sequence attackers. It is always full-trace AUC minus claim-only AUC; post-hoc
selection of a favorable direction is not allowed.

The report can preserve implementation claim eligibility only when pointwise
runtime trace equality held. A pointwise failure sets eligibility to false
regardless of classifier scores. Conversely, chance-level scores never set
security_proof to true. Statistical attacks are refutation tools, not a
replacement for the AETP security argument.
