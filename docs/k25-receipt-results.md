# K25: Two-history receipt privacy, not deployed anonymity

## Reproduce

Use an editable install or set PYTHONPATH to src.

```text
python tools/run_receipt_limit_study.py --grid --output artifacts/receipts/report.json
python tools/write_receipt_limit_certificate.py artifacts/receipts/proof.json
python tools/check_receipt_limit_certificate.py artifacts/receipts/proof.json
```

## What sharpened

In a synthetic control with all deadlines met, each individual receiver has
trace TV zero, but the pooled trace has TV one. The difference is correlation,
not a change in either individual delivery rate. In a separate optimizing
fixture, with zero TV permitted, one receiver without a failure indicator
allows a worst-history success of one half. Joint pooling or exposing the
failure indicator drops this to zero. At TV cap one quarter the values become
five eighths and one quarter, respectively.

## A comparison that includes the ties

Each capacity stratum examines all 136 unordered pairs with repetition of 16
private readiness patterns for two actions and two slots. Each pair gives 12
evaluations: three receiver sets, two failure indicator settings, and two TV
caps (zero and one quarter). The complete-only baseline first finds a shared
complete trace; failing this, it uses silence and spends only the stated TV
allowance on complete delivery.

| Capacity | Evaluations | Improved over baseline | Equal to baseline |
| --- | ---: | ---: | ---: |
| (1, 1) | 1,632 | 4 | 1,628 |
| (2, 1) | 1,632 | 0 | 1,632 |
| Total | 3,264 | 4 | 3,260 |

This is a narrow separation, not general performance superiority. The
research result is the ability to explain and check the boundary as observers
gain visibility. Verification is only for this declared finite arithmetic
model; neither publication of the demo nor a successful CI build is evidence
of privacy in a real deployment.
