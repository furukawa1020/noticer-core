# Action-Equivalent Provenance Attestation

## Status

Action-Equivalent Provenance Attestation (AEPA) is a candidate systems
property and a proposed AETP-preserving provenance mechanism. It connects
conservative acquisition and pipeline appraisal to action-token issuance.

AEPA is not claimed to be a new remote-attestation architecture. It borrows
the Attester, Verifier, Relying Party, Evidence, Endorsements, Reference
Values, Appraisal Policy, Attestation Results, and challenge-freshness
concepts from RATS and related attestation work. It does not claim
world-first status, perfect sensor authenticity, cryptographically verified
Polar samples, or proof that a signal came from a human.

## Problem

The existing trusted path begins after an EvidencePermit has been created:

~~~text
Private Evidence
-> EvidencePermit
-> AETP Admission
-> ATv2
-> APLOT
-> Verifier
-> Menfugu
~~~

That path cannot detect a collector that substitutes a recorded waveform,
uses an unapproved feature schema, changes an evidence configuration, or
binds an old pipeline to a current token key. K5 extends the high-side
boundary:

~~~text
Private PPG / ACC Acquisition
-> Signal Quality and Transparent Features
-> K1 Evidence Engine
-> EvidencePermit
-> AEPA Provenance Lease Guard
-> existing AETP / ATv2 / APLOT / Menfugu path
~~~

K5 reuses the existing private observation, evidence permit, action
semantics, token protocol, key hierarchy, transport, verifier, and actuator.
It must not create parallel versions of those types or state machines.

## RATS role mapping

| Role | K5 component | Responsibility |
|---|---|---|
| Attester | Noticer Collector | Manage a private acquisition session, measure the public pipeline, prove session-key possession, and answer a fresh challenge |
| Verifier | Noticer Provenance Verifier | Verify evidence, endorsements, reference values, challenge freshness, bindings, and conservatively derive an assurance profile |
| Relying Party | Noticer Provenance Lease Guard | Refuse production action-token admission unless a valid lease matches the service, epoch, policy, pipeline, and ATv2 key |

The Android attestation adapter can support appraisal of key and platform
state. It does not prove that every PPG sample came from a Polar sensor, that
every sample traversed the measured pipeline, that a sensor was worn, or
that an optical spoof did not occur.

## Assurance is a product, not a score

The public assurance result has five independently ordered axes:

~~~text
source
collector key
boot state
pipeline
freshness
~~~

An actual profile satisfies a required profile only when every actual
component is at least the corresponding required component. Incomparable
profiles remain incomparable. No weighted sum, overall level, request
parameter, adapter name, or successful connection may silently upgrade
another axis.

In particular:

- a Polar Verity Sense adapter is never stronger than
  PairedCommercialSensor without independently verifiable sensor-side
  signatures;
- a software attester cannot produce TeeBacked or StrongBoxBacked;
- requesting StrongBox does not demonstrate that StrongBox was used;
- an Android collector does not produce RuntimeProofOfExecution without
  an actual proof-of-execution mechanism;
- SignalQuality::Good does not mean confirmed human origin;
- low empirical spoof risk does not mean genuine human signal.

ProductionRequired is the default mode. LabUnattested is explicit, must be
recorded as LAB_UNATTESTED, and cannot fall through into a production claim.

## Measurements and declassification

Three data classes are separated:

| Class | Examples | Release rule |
|---|---|---|
| Private | Raw PPG/ACC, exact timestamps and gaps, features, baseline values, evidence trajectory, private ready slot | Never placed in evidence, lease, token, or public artifacts |
| Verifier-only | Pairwise sensor alias, private baseline commitment, exact setting digest, app-signing digest, attestation chain | Used for appraisal; not copied into the public lease |
| Public | Pipeline measurement hash, assurance categories, pairwise service alias, public epoch, policy hash, ATv2 key ID | Fixed-schema release permitted |

The public pipeline measurement describes approved software, algorithms,
schemas, and policies. It excludes a private baseline hash, raw-signal hash,
sensor serial, BLE address, stable Android identifier, exact acquisition
time, and exact sample count.

## Provenance lease

The Noticer Provenance Lease v1 (NPL1) is a fixed 256-byte appraisal result.
It binds a public epoch schedule, pairwise service alias, ATv2 key, public
pipeline measurement, assurance digest, and claim policy. It contains no
private acquisition measurement or stable device identifier.

A lease is issued on a public epoch schedule, not in response to an action.
Lease failure prevents an action ATv2 while the existing public cover
schedule continues. Detailed private failure reasons are not exposed to the
network observer.

## Action/provenance equivalence

For private acquisition histories H0 and H1, define H0 equivalent_AP H1 if
and only if all of the following public inputs are equal:

~~~text
ActionSemantics(H0) = ActionSemantics(H1)
PublicPipelineMeasurement(H0) = PublicPipelineMeasurement(H1)
AssuranceProfile(H0) = AssuranceProfile(H1)
PublicContext(H0) = PublicContext(H1)
EnrolledAttesterState(H0) = EnrolledAttesterState(H1)
~~~

Raw morphology, exact baseline values, exact evidence margin, exact sample
count, private gaps and timestamps, private context path, and private ready
slot may differ.

## Security game

1. An adversary selects H0 and H1 satisfying the equivalence relation.
2. The challenger samples b uniformly.
3. The challenger runs provenance, token, and transport processing for Hb
   under a coupled challenge, attester state, and public context.
4. The adversary observes lease bytes and timing, public assurance and
   pipeline semantics, ATv2 public trace, APLOT trace, authorized-service
   view, colluding-service views, and longitudinal public views.
5. The adversary outputs a guess.

The distinguishing advantage is:

~~~text
abs(Pr[guess = b] - 1/2)
~~~

For a coupled deterministic Tier A execution, K5 additionally requires
pointwise congruence:

~~~text
H0 equivalent_AP H1
implies
PublicProvenanceTrace(H0) = PublicProvenanceTrace(H1)
~~~

This includes lease bytes, lease schedule, ATv2 trace, and K4 transport
trace. The statistical attack evaluation supplements rather than replaces
this structural invariant.

## Adversaries and failure response

| Attack | Required response |
|---|---|
| Recorded source replaces live adapter | Source assurance or pipeline appraisal fails |
| Timestamp rollback, duplicate batch, cross-session splice | Private acquisition state rejects without updating K1 |
| Feature, quality, baseline, or evidence configuration downgrade | Pipeline measurement mismatch |
| Stale verifier challenge | Evidence rejected |
| Collector key or attestation level overclaim | Profile capped by verified evidence |
| ATv2 issuer-key substitution | Lease guard rejects |
| Missing or expired lease | No action ATv2 |
| Action-correlated lease renewal | Protocol violation |
| Public raw hash, exact timing/count, or stable identifier | AEPA violation |
| Physical optical spoof | Not guaranteed; report empirical risk and verification tier |

Every failure is fail closed for action authority. A rejected provenance
path must not change the public cover cadence or reveal a detailed reason.

## Prior-work boundary

K5 borrows sensor access-control concepts from VERSA, proof-of-execution
concepts from APEX, data-generation and processing provenance concepts from
DIAT, and architecture and claim terminology from RATS/EAT. It does not
claim those mechanisms as new.

The candidate contribution under evaluation is the exact combination of:

~~~text
AETP action equivalence
+ biosignal-pipeline provenance
+ conservative assurance downgrade prevention
+ private measurement redaction
+ fixed public provenance result
+ action-token issuance binding
~~~

K5 does not implement full proof of execution, TEE-contained PPG
processing, sensor-side signatures, zero-knowledge attestation, globally
anonymous Android enrollment, or perfect physical liveness.

## Verification tiers

| Tier | Requirement | Initial status |
|---|---|---|
| A | Synthetic acquisition, reference software attester, verifier, fixed lease, congruence, source attacks, ATv2/K4 integration | NOT_VERIFIED until K5 software issues pass |
| B | Live Polar PPG+ACC for at least 30 minutes and K1 processing | NOT_VERIFIED |
| C | Hardware-backed Android key, fresh challenge, chain, security level, boot and app identity appraisal | NOT_VERIFIED |
| D | Live acquisition through actual APLOT and physical Menfugu action with replay rejection | NOT_VERIFIED |
| S3 | Physical optical spoof apparatus | PHYSICAL_OPTICAL_SPOOF_NOT_VERIFIED |

CI or simulation cannot upgrade Tier B, C, D, or S3.

## Falsification and kill conditions

The AEPA claim is rejected or reduced if any of these occurs:

- provenance adds a private raw hash, exact timing/count, stable sensor ID,
  or private baseline hash to a public result;
- action-equivalent histories produce different public provenance, token,
  or transport traces under coupled public inputs;
- an unapproved adapter, stale challenge, pipeline mismatch, assurance
  downgrade, or ATv2 key substitution is accepted;
- production action authority can be obtained without a validated lease;
- a lease does not bind meaningful appraisal evidence to action issuance;
- Polar data is described as sensor-signed without a verifiable signature;
- Android key attestation is described as sample-origin proof;
- a hardware tier is reported as verified without the required hardware
  run.

## Incremental delivery

K5 is intentionally split into separately mergeable issues:

~~~text
K5-00 claim boundary
-> K5-01 assurance profile
-> K5-02 acquisition
-> K5-03 features and quality
-> K5-04 K1 bridge

K5-01 -> K5-05 pipeline measurement
K5-05 -> K5-06 evidence
K5-06 -> K5-07 appraisal
K5-07 -> K5-08 lease
K5-04 + K5-08 -> K5-09 ATv2 lease guard
K5-09 -> K5-10 congruence simulation
K5-10 -> K5-11 attacks
K5-02 + K5-03 + K5-04 + K5-07 -> K5-12 Android collector
K5-00..K5-12 -> K5-13 Tier A integration
K5-12 + K5-13 -> K5-14 hardware tiers
~~~

Each issue uses its own branch, Japanese commits, Draft PR, CI result, and
merge commit. No issue may silently widen a claim established here.
