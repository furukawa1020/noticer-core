# Private Atypicality Evidence Engine

K1 is the only canonical producer of a local `EvidencePermit`. It does not issue an
Atypicality Token and exposes no score, p-value, e-value, feature, context, baseline statistic,
semantic label, or confidence value.

## Boundary

```text
PrivateObservation
  -> pre-authorized ContextKey
  -> immutable AnchorBaseline score
  -> randomized conformal rank
  -> log-domain mixture e-process
  -> persistence / quality / time / epoch gates
  -> single-use EvidencePermit
```

`PrivateFeatureVector`, `PrivateObservation`, and `EvidencePermit` have no serde traits.
Private feature fields and permit fields are inaccessible outside their defining crate.
The permit constructor is private and the permit is neither `Clone` nor `Copy`.

## State transition

```text
step : EvidenceState x PrivateObservation x PrivateRng
     -> EvidenceState x EvidenceDecision
```

Logical time must increase strictly. Unknown context, unavailable baseline, insufficient
quality, exhausted epoch, and incomplete persistence produce no permit. Numerical failure,
dimension mismatch, invalid alpha state, and time rollback fail closed.

## Context and alpha spending

Context is selected before scoring and represented by an opaque key. Calibration histories
never cross contexts. Context weights must be positive and sum to at most one. Epoch `k`
receives `alpha_total * context_weight * 6 / (pi^2 * k^2)`. Restarting an epoch must be explicit
and predetermined; data-dependent restart is outside the candidate guarantee.

## Persistence and bounded memory

An e-threshold crossing is necessary but insufficient. The configured number of recent
p-values must also satisfy `p <= p_max`. One epoch can issue at most one permit. Monitoring
history is bounded by `max_monitoring_steps`; reaching the horizon closes issuance rather than
silently recycling alpha.

## EvidencePermit versus Atypicality Token

The permit is a local ownership object proving only that K1 gates were satisfied. K2/K3 may
consume it to request a bounded action token. They cannot reconstruct the private evidence
from it. A permit is not a diagnosis, physiological description, or remotely verifiable proof.

