# K5-11 Provenance Attack Protocol

## Scope

This protocol is a deterministic synthetic implementation smoke. It confirms
that the attack harness detects deliberate provenance leaks and that modeled
AEPA views remain indistinguishable under counterfactual-pair group splits. It
is not scientific evidence about a deployed sensor or human population.

## Inference experiment

Each counterfactual pair contains both class labels and is assigned as one unit
to train, validation, or test. The API exposes no random-row split. The same
pair manifest is reused for all mechanisms, views, and models.

The mechanisms are AEPA and six deliberately leaky controls, B0 RawInputHash,
B1 RawFeatureVector, B2 ExactSampleCount, B3 ExactAcquisitionTiming, B4
StableSensorIdentifier, and B5 GlobalCollectorKey. The attacker views are A0
LeaseOnly through A5 Longitudinal.

Four fixed models are evaluated without test-set model selection:

1. LogisticRegression.
2. RandomForestClassifier.
3. ExtraTreesClassifier.
4. HistGradientBoostingClassifier.

Artifacts report balanced accuracy, ROC-AUC, F1, attack advantage, and a 95%
counterfactual-pair bootstrap interval for ROC-AUC. At least three leaky
baselines must reach ROC-AUC 0.80, while every modeled AEPA view must have an
upper interval bound no greater than 0.60.

## Source and spoof experiment

S0 through S9 cover recorded replay, phase shift, amplitude scaling, template
injection, periodic replay, ambient injection, PPG-ACC mismatch, assurance
downgrade, lease substitution, and ATv2-key substitution. Each attack is run
for a fixed number of trials through an ordered fail-closed gate model. The
report includes acceptance, source rejection, rejection latency, false action,
and unauthorized action counts. A benign C0 control must pass so that all-zero
attack acceptance is not caused by a dead harness.

## Artifact boundary

Only aggregate metrics, pair split assignments, public feature names, attack
class labels, criteria, and plots are persisted. The validator rejects exact
schema tokens for raw PPG/ACC, private feature vectors, exact acquisition
values, private context values, sensor identifiers, BLE addresses, and private
baselines. Generated artifacts remain under `artifacts/` and are not committed.

## Non-claims

The source and spoof outcomes are modeled software-gate results. Live Polar
capture, adaptive over-the-air spoofing, Android hardware attestation, physical
sample origin, and population-level privacy remain unverified until their
dedicated K5 tasks and hardware tiers are completed.
