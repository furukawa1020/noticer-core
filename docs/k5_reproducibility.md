# K5 Tier A end-to-end reproducibility

## Scope and claim boundary

K5-13 connects the existing synthetic acquisition, K1 evidence bridge, NPL1
appraisal, production lease guard, ATv2, K4 transport, and virtual Menfugu into
one deterministic software run. It adds no new defense and does not turn a
software simulation into hardware evidence.

The result is a candidate end-to-end security construction and a proposed
evaluation protocol. To the best of our literature review, we found no prior
work combining these exact action-equivalent provenance, lease, trace-shaping,
and actuation semantics. This is not a `world-first` claim. The prior-work
boundaries in `docs/aetp_prior_work_boundary.md`, `docs/claim_matrix.md`, and
`docs/action_equivalent_provenance_attestation.md` remain controlling.

## One-command Tier A run

```bash
python tools/run_k5_provenance.py \
  --config-root configs/k5 \
  --output artifacts/k5/tier_a/latest \
  --seed 20260814
```

PowerShell accepts the same arguments on one line. Paths are resolved with
`pathlib.Path`; no shell-specific command construction is used. The run executes
real repository tests for acquisition, K1, NPL1, and the production lease guard,
then invokes the existing provenance simulator and K4 demo. Finally,
`noticer-k5-demo` inspects the public summaries and writes:

- `public/summary.json`
- `public/scenarios.csv`
- `public/manifest.json`
- `software_gates.json`
- upstream public simulator artifacts under `provenance/` and `k4/`

The entire output directory is generated and ignored by Git. The committed JSON
Schema is `schemas/k5_tier_a_public.schema.json`.

## Pipeline inspector

| Stage | Evidence used in Tier A | Hardware claim |
|---|---|---|
| Synthetic acquisition | `noticer-acquisition-core` tests | None |
| K1 EvidencePermit bridge | `noticer-evidence-bridge` tests | None |
| NPL1 appraisal | `noticer-provenance-verifier` tests | None |
| Production lease | `production_lease_guard` integration test | None |
| ATv2 | 24 P0-P5 counterfactual cases | None |
| K4 | observer/execution trace equality and replay rejection | None |
| Virtual Menfugu | one authorized semantic action in simulation | None |

The inspector accepts only exact 1.0 congruence rates and the fixed upstream
schemas. A failed software gate cannot be hidden by a later successful stage.

## Lease inspector scenarios

| Scenario | Expected public result | Forbidden result |
|---|---|---|
| `valid` | one authorized action | zero or multiple actions |
| `no_lease` | rejected cover | action |
| `expired` | rejected cover | action |
| `downgrade` | rejected cover | action |
| `wrong_key` | rejected cover | action |
| `replay` | rejected cover without actuation | repeated action |
| `lab_unattested` | rejected cover in production | production admission |

The scenario summary is not a replacement for the production integration test.
It is an inspector over that test gate and the K4 replay result.

## Public artifact validator

The validator recursively rejects exact private-field keys, including raw PPG or
ACC samples, baseline values, private histories, device identifiers, attestation
chains, signatures, serialized leases/tokens, and key material. It permits the
meta-field `private_field_count`, which must equal zero. The gate manifest stores
only stable gate IDs and `PASSED`/`FAILED`; commands, stdout, and stderr are not
artifact fields.

## Source spoof threat model

| Threat | Tier A response | Residual boundary |
|---|---|---|
| Replayed synthetic batch | monotonic/replay tests reject | physical BLE replay is Tier B |
| Different commercial sensor | source ceiling prevents SensorSigned claim | pairing is not manufacturer attestation |
| Stolen device identifier | identifier is neither artifact nor identity proof | real pairing UX is Tier B |
| Forged Android evidence | K1/NPL1 appraisal tests reject malformed evidence | hardware chain verification is Tier C |
| App downgrade | profile binding rejects | OS rollback resistance is Tier C |
| Key substitution | key binding rejects | keystore extraction testing is Tier C |
| Lease replay | single-consumption and epoch checks reject | distributed verifier state is Tier D |
| Lab token promotion | `LAB_UNATTESTED` is production-inadmissible | build/signing operations are Tier C |
| Skin-contact spoof | never used as sole worn detector | worn detection accuracy is Tier B/D |
| Trace observer inference | counterfactual observer traces must match | RF side channels and packet loss are Tier B/D |

## Hardware reproduction boundary

`configs/k5/hardware.example.yaml` contains no device identifier. A local operator
may supply `NOTICER_POLAR_DEVICE_ID` without writing it to disk. The committed
configuration and every Tier A artifact must retain these statuses:

| Tier | Required future evidence | Current status |
|---|---|---|
| A | deterministic software and virtual transport | `VERIFIED` only after the run passes |
| B | Verity Sense + Android BLE, loss, latency, sustained collection | `NOT_VERIFIED` |
| C | hardware-backed key attestation, appraiser, rollback/build controls | `NOT_VERIFIED` |
| D | field deployment, adaptive attacks, false/unauthorized actions | `NOT_VERIFIED` |

K5-14 (#19) owns Tier B-D measurement. K5-13 must never update those fields to
`VERIFIED`.

## Twenty rejection arguments

| ID | Likely rejection argument | Required answer before submission | Current disposition |
|---|---|---|---|
| RA-01 | This is only traffic padding | Show action-equivalent provenance plus semantic actuation | Addressed in Tier A |
| RA-02 | This is only Pufferfish privacy | State the mechanism and system-boundary differences | Documented, literature audit remains |
| RA-03 | Conditional MI would suffice | Demonstrate whole-trace attack and action semantics | Evaluation protocol exists |
| RA-04 | Provenance reveals the user | Keep provenance quotient public and private evidence local | Tier A checked |
| RA-05 | Pairing proves manufacturer identity | Do not exceed `PairedCommercialSensor` | Tier A checked |
| RA-06 | Android attestation proves biosignal origin | Separate platform key evidence from sensor evidence | Documented |
| RA-07 | Synthetic success predicts hardware success | Keep Tier B-D `NOT_VERIFIED` | Enforced |
| RA-08 | The valid path can execute twice | Require lease consumption and replay rejection | Tier A checked |
| RA-09 | Invalid paths leak through timing | Require full cover trace, not an early error | Tier A checked |
| RA-10 | Lab output can reach production | Make `LAB_UNATTESTED` inadmissible | Tier A checked |
| RA-11 | A downgraded profile is equivalent | Bind profile/version into appraisal and lease | Tier A checked |
| RA-12 | A substituted key is harmless | Bind appraised key through NPL1 and token issuer | Tier A checked |
| RA-13 | Artifact hashes hide private data | Publish only approved public hashes and booleans | Validator checked |
| RA-14 | Logs reconstruct private histories | Keep commands/output out of artifacts and ban collector logs | Enforced |
| RA-15 | Skin contact proves wearing | Treat it only as one unreliable signal | Documented |
| RA-16 | Session simulation misses adaptive attacks | Run S0-S9 attacks and future physical attacks | Software done; hardware remains |
| RA-17 | Menfugu authorization is not semantic safety | Bound the allowed action and false-action metric | Virtual only; field remains |
| RA-18 | One device profile cannot generalize | Declare Verity Sense profile and source ceiling | Documented |
| RA-19 | Reproducibility depends on hidden state | Fix seed/config/schema and reject secret config | Enforced |
| RA-20 | Novelty language exceeds evidence | Use candidate/proposed wording until audit finishes | Enforced by document policy |

## GO / PIVOT / KILL

`GO_TIER_A` means only that all software gates, seven scenarios, public artifact
validation, 24 counterfactual cases, K4 replay rejection, and virtual Menfugu pass.

`PIVOT` applies when the run is fail-closed with no false action but a software
gate or congruence claim fails. The mechanism or evaluation must be revised.

`KILL` applies when a private field reaches a public artifact, an invalid scenario
causes an action, replay actuates, or, after all software gates pass, the valid
scenario cannot produce exactly one bounded action. No hardware or publication
claim may proceed from that run.
