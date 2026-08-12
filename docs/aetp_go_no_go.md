# AETP Go / Pivot / Kill Gate

## GO

- pointwise coupled network, service, and collusion equality is 100%
- ImmediateRelease timing AUC is at least 0.80
- AETS full-trace balanced-accuracy 95% interval contains 0.50 and upper bound is at most 0.58
- AETS collusion and 64-bucket upper bounds are at most 0.60
- action utility is 100%, with zero misses and duplicates
- fixed packet length, cadence, and private-field checks pass
- CAPE and Pufferfish boundaries remain explainable without general-theory claims

## PIVOT

Pivot to approximate AETP, coarser semantics, or a bounded-rate mechanism if deadlines, bandwidth,
collusion, or adaptive suppression prevent exact equality. Record overhead and failed criteria.

## KILL

Kill the central claim if the result reduces to padding, cannot be distinguished from existing
CAPE evaluation, action-equivalent classes are unusable, utility necessarily leaks private time,
collusion inevitably reconstructs it, or only a type boundary remains.

## Current decision rule

`report.json` computes the gate from held-out attacks and structural reports. A GO on synthetic
K2 evidence authorizes real-data and transport evaluation; it is not a publication-level privacy
conclusion. Any KILL condition must be recorded here rather than hidden.
