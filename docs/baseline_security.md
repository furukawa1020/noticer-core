# Baseline Security

The personal baseline controls future physical and informational authority. Updating it is a
security-sensitive operation, not ordinary model adaptation.

## Explicit split

Reference samples fix robust location and scale. Separate calibration samples initialize rank
history. Monitoring samples are scored afterward. Reused sample IDs across reference and
calibration are rejected.

## Immutable anchor

For each dimension, the anchor uses median location and
`max(1.4826 * MAD, scale_floor)`. Nonconformity is capped standardized RMS distance. The anchor
is immutable for an evidence epoch, so the current observation cannot normalize itself before
its own decision.

## Shadow baseline

The shadow observes benign drift with clipped influence. It cannot suppress an issuance,
mutate the anchor, or promote itself. Updates require sufficient quality, no permit, low
private evidence, no quarantine, remaining update budget, and bounded anchor divergence.

Abrupt or cumulative divergence freezes the shadow and records a security event. A bounded
rollback queue supports recovery. Recalibration creates a sanitized local proposal; promotion
must be explicit, creates a new anchor version and evidence epoch, advances alpha spending,
and retains a rollback point.

## Threats and limitations

Evaluations must cover abrupt poisoning, slow-boil poisoning, context manipulation, update
budget exhaustion, alert-adjacent quarantine, flooding, suppression, and recovery. Influence
clipping limits each accepted update but does not by itself prove robustness against adaptive
long-horizon attackers.

