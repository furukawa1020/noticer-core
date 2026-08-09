# Statistical Guarantees and Non-Guarantees

## Candidate guarantee

`ExchangeabilityAssumed` means that a candidate sequential guarantee is evaluated under all
of these assumptions:

- reference data are independent of monitoring data;
- the score function and anchor remain fixed during the evidence epoch;
- calibration and monitoring scores are exchangeable under the null;
- randomized tie breaking is independent and private;
- context is selected without inspecting the current physiological score;
- the shadow baseline never affects formal scoring;
- restarts and context alpha weights are predetermined;
- alpha is not reused across epochs.

The marker records assumptions; it is not a mathematical proof that deployment data satisfy
them. Empirical false-permit measurements are reported separately.

## Randomized rank

For a current score `s_t`, the history and current score define:

```text
p_t = (strictly_greater + U_t * equal_including_current) / n_t
```

where `U_t` is private independent uniform randomness. The implementation enforces
`0 < p_t <= 1` and rejects non-finite arithmetic.

## Mixture e-process

For each configured `0 < epsilon < 1`:

```text
log E_t(epsilon) = log E_(t-1)(epsilon)
                 + log(epsilon)
                 + (epsilon - 1) log(p_t)
```

The mixture uses normalized positive weights and log-sum-exp. No permit is issued after NaN,
infinity, zero p-value, or invalid configuration.

## No formal guarantee

The engine must downgrade to `EmpiricalOnly` when any relevant condition is present, including:

- global fallback context;
- adaptive baseline used for scoring;
- physiology-dependent context selection;
- data-dependent restart;
- uncontrolled drift or adversarial observations;
- violated exchangeability;
- reused or untracked alpha budget.

The 7-scenario demo is a deterministic smoke artifact, not evidence of clinical validity or a
publication-level false-release bound.

