# Independent PLD and f-DP offline audit

`quotient-offline-auditor` independently reconstructs privacy loss from a discrete PLD rather than reusing the runtime AQ-RDP accountant.

It validates both P and induced Q normalization, performs explicit PLD convolution, evaluates hockey-stick divergence, numerically inverts epsilon at a requested delta, and emits likelihood-ratio ROC points for f-DP inspection. The auditor reports an underestimate whenever the runtime upper bound plus the declared numerical tolerance is below the independently reconstructed PLD epsilon.

This is an offline cross-check, not a replacement for runtime enforcement. Its input PLD must be derived independently from the certified mechanism semantics. Atom-count caps fail closed before convolution can cause unbounded resource use.
