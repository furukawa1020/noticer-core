# K7 AQRS research contract

Status: **FROZEN**  
Contract version: 1  
Freeze date: 2026-08-17  
Parent Issue: #74  
Implementation Issue: #78

## 1. Purpose

This contract freezes the K7 hypothesis, benchmark-family split, seeds, resource limits,
metrics, outcome taxonomy, and GO/PIVOT/KILL gates before K7 synthesis and attack experiments.
It prevents a successful-looking report from being produced by changing a threshold, dropping a
hard case, or converting timeout into a negative result after observing outcomes.

The machine-readable source is
`configs/quotient_forge/k7_research.yaml`. Its deterministic public manifest is validated against
`schemas/k7_research_manifest_public.schema.json`.

## 2. Frozen hypothesis

The tested hypothesis is:

> An authorized-action quotient over private histories, complete declared observer traces, and
> hard action/deadline/bounded-fault utility form a useful bounded release-mechanism synthesis
> problem.

The experiment must test usefulness through automatic discovery, checker-validity, resource
behavior, attack evaluation, and comparison. Implementing another backend does not itself satisfy
the hypothesis.

## 3. Evidence boundary

K7 remains software-only. It can establish behavior of finite models, checkers, generated
runtimes, and implementation-derived software traces. It cannot upgrade Polar, Android
attestation, BLE hardware, Menfugu hardware, or optical-spoof tiers from `NOT_VERIFIED`.

The following evidence levels remain distinct:

| Level | Evidence |
|---|---|
| E0 | Specification or documentation |
| E1 | Unit, property, mutation, and CI tests |
| E2 | Frozen synthetic or implementation-derived software experiment |
| E3 | Comparative experiment on nontrivial held-out models |
| E4 | Physical deployment evidence outside K7 |

No E0-E3 result is reported as E4.

## 4. Frozen split

The split unit is `spec_family`. Row-random splitting is prohibited. A generated variant belongs
to the same split as its family. Each split contains eight families, and no family appears in two
splits.

| Split | Noticer families | Generic families | Negative families |
|---|---|---|---|
| Train | `noticer_aets_fixed_cadence`, `noticer_aplot_bounded_loss`, `noticer_atv2_action_window` | `generic_delayed_notification`, `generic_fixed_size_release`, `generic_public_retry` | `negative_missing_authorized_output`, `negative_secret_dependent_retry` |
| Development | `noticer_aepa_public_context`, `noticer_service_separation`, `noticer_reconnect_normalization` | `generic_private_scheduler`, `generic_medical_alert` | `negative_impossible_deadline`, `negative_failure_leak`, `negative_quotient_merge` |
| Held out | `noticer_multiservice_collusion`, `noticer_longitudinal_handoff` | `generic_smart_home_actuator`, `generic_activity_actuator`, `generic_fault_tolerant_alarm` | `negative_private_carryover`, `negative_observer_omission`, `negative_unauthorized_cover_action` |

K7-08 must implement these exact family IDs. Replacing a family after observing results requires a
new contract version. Held-out families are public for reproducibility but cannot guide backend or
repair tuning.

## 5. Seed registry

| Purpose | Seed |
|---|---:|
| Catalog | 42001 |
| Synthesis | 42002 |
| Attack | 42003 |
| Split | 42004 |
| Mutation | 42005 |

All randomized work must derive a named child seed from one registry entry and record that name.
Using an unrecorded random seed invalidates reproducibility for that run.

## 6. Resource contract

| Limit | Value |
|---|---:|
| Solver time | 300 seconds |
| Checker time | 60 seconds |
| Peak memory | 4096 MiB |
| Candidate count | 1,000,000 |
| Checker nodes | 10,000,000 |
| Public manifest size | 65,536 bytes |

Limit exhaustion is an inconclusive result. Partial candidates do not become certificates.

## 7. Frozen gates

### Scalability

- At least one measured backend must attempt 12 plant states, 8 machine states, horizon 64, and
  four observers under the frozen resource contract.
- Failure to complete is reported as timeout or resource exhaustion, not as success.

### Discovery

- At least one held-out valid transducer must be found.
- It must not be equivalent to an author-supplied schedule template under the declared canonical
  equivalence check.

### Independent assurance

- The independent semantics work must detect at least ten intentional checker mutants.
- Native `no_std`, WASM, and certificate-reference execution permit zero cross-target mismatch.

### Attack

- At least 200 counterfactual pair groups are required.
- Confidence level is 0.95.
- Full-trace minus claim-only attack advantage must not exceed 0.05 for a passing protected case.
- The leaky control advantage must be at least 0.30, or the attacker is not informative.
- Pointwise structural divergence always overrides a chance-level classifier result.

These are preregistered engineering gates, not universal security constants.

## 8. Outcome taxonomy

| Class | Outcomes |
|---|---|
| Success | `CERTIFICATE_VALID` |
| Bounded negative | `UNSAT_AT_BOUND`, `UNREALIZABLE_WITHIN_BOUNDS` |
| Inconclusive | `TIMEOUT`, `RESOURCE_LIMIT`, `SOLVER_UNAVAILABLE`, `SOLVER_UNKNOWN`, `CHECKER_INCONCLUSIVE` |
| Invalid | `INVALID_SPEC`, `INVALID_CANDIDATE`, `INVALID_CERTIFICATE`, `MALFORMED_SOLVER_OUTPUT` |

The classes are disjoint. `SAT` from a solver is only a candidate state and is not a success
outcome until the independent checker accepts it.

## 9. Frozen metrics

Every applicable experiment records checker and solver status, wall and CPU time, peak RSS,
candidate count, checker nodes, solver calls, pointwise divergences, utility violations, attack
AUC/advantage/excess advantage, and the declared cost vector. Unsupported metrics remain null with
an explicit reason; they are not silently omitted.

Warmup count is one and measured repetition count is five. K7-09 may not choose repetitions after
seeing variance.

## 10. Public artifact boundary

The public manifest contains only version/state, six domain-separated hashes, split policy,
outcome registry, aggregate family counts, and `private_field_count: 0`. It excludes family rows,
private histories, biosignals, identifiers, keys, certificate chains, and token bytes.

Every hash uses canonical sorted ASCII JSON and a distinct domain string. Wall clock time, host
path, username, process ID, and map iteration order do not enter a hash.

Generated manifests belong under `artifacts/` and are not committed.

## 11. Reproduction

Windows:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe tools\build_k7_research_manifest.py build `
  --config configs\quotient_forge\k7_research.yaml `
  --output artifacts\k7\research-manifest.json
.\.venv\Scripts\python.exe tools\build_k7_research_manifest.py validate `
  --config configs\quotient_forge\k7_research.yaml `
  --input artifacts\k7\research-manifest.json
```

Linux:

```bash
PYTHONPATH=src .venv/bin/python tools/build_k7_research_manifest.py build \
  --config configs/quotient_forge/k7_research.yaml \
  --output artifacts/k7/research-manifest.json
PYTHONPATH=src .venv/bin/python tools/build_k7_research_manifest.py validate \
  --config configs/quotient_forge/k7_research.yaml \
  --input artifacts/k7/research-manifest.json
```

Writing the same path twice is an idempotent no-op. A different existing file is never
overwritten.

## 12. Amendment rule

Version 1 is frozen before K7-01 onward. A correction requires all of the following:

- a new contract version;
- a written reason and changed-field list;
- new domain hashes;
- preservation of the old contract and results;
- an explicit statement whether any prior result was observed before amendment.

Silent edits invalidate the affected K7 comparison.

## 13. Non-claims and falsification

This contract does not establish infinite-state synthesis, unbounded privacy, physical deployment
security, solver correctness, or priority over general synthesis and traffic-shaping research.

K7 remains PIVOT or becomes KILL if the held-out discovery, independent assurance, translation,
attack control, or resource-reporting gates fail. CI completion alone cannot produce GO.

