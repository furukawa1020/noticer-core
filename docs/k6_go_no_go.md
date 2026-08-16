# K6 Go / Pivot / Kill decision

Decision: **PIVOT**  
Decision date: 2026-08-17  
Evaluated baseline: `main` at K6-13 merge `cb24588`  
Issue: #57

## 1. Decision

K6 passes as a reproducible bounded software artifact, but it does not yet pass as an empirical
claim that QuotientForge is a scalable synthesis contribution.

The project therefore pivots to the narrower center:

> QuotientForge is a domain-specific bounded AQRS checker, typed repair engine, certificate
> pipeline, and public-only `no_std` code generator, with small-model synthesis as a reference
> backend.

The broader compiler claim can return only after external-solver experiments, direct prior-work
comparisons, nontrivial automatic discovery, and deployment-representative trace evaluation.
This is a scope correction, not a relabeling of missing evidence as success.

No current observation triggers KILL. The checker rejects known leaky mechanisms, repair is
rechecked, generated APIs exclude private input, and the Noticer adapter preserves existing type
ownership. These facts keep the narrower artifact useful.

## 2. Evidence levels

| Level | Meaning | Current state |
|---|---|---|
| E0 | Design contract or documentation only | Complete for all K6 components |
| E1 | Unit/integration test and CI evidence | Present for Rust, Python, and Studio paths |
| E2 | Reproducible synthetic protocol smoke | Present for K6-12 |
| E3 | Comparative experiment on nontrivial system models | Missing |
| E4 | Real biosignal, transport, or hardware deployment evidence | Out of K6 scope and missing |

Research claims in this document do not exceed E2. E0 documentation is not treated as proof, and
E2 constructed data is not treated as deployment privacy evidence.

## 3. Reproduced K6-12 snapshot

The configured smoke was run from the repository checkout with the existing virtual environment:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe tools\run_quotient_forge_benchmark.py `
  --config configs\quotient_forge\benchmark_smoke.yaml
```

The package must otherwise be installed before using the shorter command documented by the tool.
The first bare-system Python invocation failed because `noticer_core` was not installed, and a
second invocation with only `PYTHONPATH` failed because `numpy` was absent from that interpreter.
Those environment failures are not benchmark failures, but they are relevant reproducibility
conditions.

Generated run: `20260816T230429Z-3e2170c7` under the ignored artifact directory.

| Measurement | Observed value | Interpretation |
|---|---:|---|
| Total cases | 11 | Catalog wiring smoke |
| Noticer cases | 4 | All matched expected realizability |
| Generic cases | 4 | All matched expected realizability |
| Unrealizable cases | 3 | All rejected within declared synthetic bounds |
| Protected pointwise equality minimum | 1.0 | Constructed protected pairs were equal |
| Protected maximum ROC-AUC | 0.500 | Four configured attackers on constructed pairs |
| Leaky-control minimum ROC-AUC | 1.000 | Intentional leak remained detectable |
| Split unit | `counterfactual_pair_id` | Pair-disjoint; no row-random split |
| Attack models | 4 | Logistic regression, random forest, extra trees, histogram gradient boosting |
| Scalability axes | 5 | Plant, machine, horizon, observer, fault smoke axes |
| Recorded timeout rows | 7 | Deterministic resource-limit behavior, not solver performance |
| Ablations | 6 | Wiring-level mechanism removal |
| Acceptance aggregate | `all_criteria_passed=true` | Harness smoke passed |

The AUC values are expected consequences of deliberately equal or deliberately leaking synthetic
features. They establish that the attack harness can distinguish the control. They do not establish
privacy on real traces, resistance to adaptive attackers, or superiority over prior systems.

## 4. Original GO conditions

| Condition | Status | Evidence or gap |
|---|---|---|
| ImmediateRelease produces a counterexample | Met at E1 | Noticer adapter and product-checker tests |
| A repaired plan becomes checker-valid | Met at E1 | Typed repair tests; bounded operator set only |
| Handwritten AETS is valid | Met at E1 | Same finite checker path |
| Handwritten APLOT is valid under bounded public loss | Met at E1 | Same finite checker path |
| At least four Noticer cases | Met at E2 | Four synthetic catalog entries |
| At least four generic cases | Met at E2 | Four synthetic catalog entries |
| At least three unrealizable cases | Met at E2 | Three bounded synthetic negatives |
| Certificate tamper is rejected | Partial | Implemented mutations pass tests; no exhaustive mutation claim |
| Generated `no_std` crate builds | Met at E1 | Codegen integration test |
| Generated runtime matches certificate vectors | Met at E1 | Exhaustive generated transition vectors for test certificates |
| Synthesis completes at 12 plant states, 8 machine states, horizon 64 | Not met | K6-12 workload counters are not a Rust solver run |
| Quotient reduction improves measured solver search | Not met | Synthetic ablation is not a solver comparison |
| CEGIS improves over one-shot solving | Not met | No controlled external-solver experiment |
| Repair reduces attack AUC to chance | Partial at E2 | Constructed smoke only |
| A non-handwritten transducer is discovered on a nontrivial case | Not met | Small reference tests do not establish this claim |
| Cost frontier contains multiple meaningful non-dominated plans | Partial | Repair/Studio demonstrations exist; no comparative systems result |
| AETP, ATv2, and APLOT integration exists | Met at E1 | Adapter reuses project-owned public contracts |
| General HyperLTL synthesis difference is explicit | Met at E0 | Prior-work boundary narrows the claim |
| External solver path is evaluated | Not met | Solver CI remains optional and may be skipped |
| Real or deployment-representative traces are evaluated | Not met | K6-12 explicitly excludes them |

The missing synthesis, comparison, and deployment rows prevent GO.

## 5. Rejection arguments

Classification semantics:

| Class | Meaning |
|---|---|
| `Survive` | The bounded claim remains defensible after an explicit clarification |
| `Pivot` | The artifact remains useful, but the central claim must narrow or obtain new evidence |
| `Fatal` | If the condition is observed, the stated AQRS assurance or synthesis contribution fails |

| ID | Reviewer rejection argument | Class | Evidence, required evidence, or claim reduction |
|---:|---|---|---|
| R01 | This is only a domain-specific frontend for HyperLTL synthesis. | Pivot | General synthesis is prior work. Retain only the fixed AQRS IR and exact Noticer integration; add a direct encoding comparison. |
| R02 | This is bounded synthesis with different names. | Pivot | Bounds are explicit and not novel. Demonstrate that action quotient plus hard utility/fault structure changes modeling or search, otherwise center checker/repair. |
| R03 | This only asks SMT to select a Pacer-like schedule. | Survive | Pacer shaping is prior work; AQRS additionally models action equivalence and utility. A direct Pacer-style baseline is still required. |
| R04 | NetShaper already provides formal timing/size privacy. | Pivot | Do not rank exact equality above DP without a shared adjacency and observer. Claim a different semantics and compare cost/utility empirically. |
| R05 | Privacy against an observer already has bounded synthesis and certificates. | Pivot | This is the closest collision. Limit novelty to complete action-quotient traces, hard utility/fault obligations, and project bindings. |
| R06 | The action quotient is ordinary declassification. | Pivot | Declassification is established. Evaluate whether the domain-specific quotient enables useful automation; do not claim the general idea. |
| R07 | AQRS merely compiles the already-defined AETP property. | Survive | K6 is correctly an automation layer over existing project prior work. The contribution must be tool-supported construction, not a new AETP definition. |
| R08 | The certificate checker is only exhaustive testing. | Survive | Describe it as finite reachability recomputation, not a proof-assistant theorem. Report model, horizon, and resource limits with every result. |
| R09 | The guarantee ends at a bounded horizon. | Survive | The result taxonomy already limits acceptance to the horizon. Remove any unbounded or deployment-wide reading. |
| R10 | The finite abstraction does not match the generated or deployed runtime. | Fatal | Require differential trace equivalence and adapter validation. An observed mismatch invalidates the certificate claim for deployment. |
| R11 | Code generation merely prints a transition table. | Pivot | Table emission is engineering. Retain value only through certificate binding, public-only API, stable encoding, and measured integration. |
| R12 | Repair operators are manually chosen. | Survive | The closed typed operator set is explicit. Claim bounded release-IR repair, not arbitrary repair or completeness. |
| R13 | The cost objective is arbitrary and unrelated to hardware cost. | Pivot | Label it a symbolic cost model until calibrated against latency, bytes, radio time, or energy measurements. |
| R14 | Privacy is achieved only by destroying authorized action utility. | Fatal | The product checker must continue to enforce exactly-once action and deadlines. Any accepted suppress-all plan invalidates the core. |
| R15 | The synthesizer can discover only fixed schedules. | Pivot | Broaden measured mechanism families or recenter the contribution on checker/repair. Do not imply general mechanism discovery. |
| R16 | Counterexamples exist only for hand-constructed synthetic pairs. | Pivot | Add generated and implementation-derived failures with minimized witnesses. Current examples establish wiring only. |
| R17 | Results do not generalize beyond Noticer. | Pivot | Generic cases are currently toy finite models. Either build accepted external benchmarks or explicitly remain Noticer-specific. |
| R18 | The generic benchmark suite is too small and favorable. | Pivot | Add independently specified cases, negative controls, and preregistered bounds; keep current 4+3 catalog as smoke. |
| R19 | Solver scalability is too low for the claimed model size. | Pivot | Report timeout separately and narrow to checker/repair if external solver grids do not reach preregistered bounds. |
| R20 | CAQT is not a solver proof or proof-assistant derivation. | Survive | It is a versioned finite checker artifact. Remove any wording that implies a formal derivation stronger than recomputation. |
| R21 | The independent checker can contain the same semantic bug as the compiler. | Fatal | Differential implementations, mutation/fuzz tests, and eventually mechanization are needed. A shared accepted semantic error defeats assurance. |
| R22 | The Studio is a demonstration, not a research contribution. | Survive | This is already the intended role. Keep browser small-model mode out of the central contribution list. |
| R23 | Generated code may be slower than a handwritten mechanism. | Survive | Performance is an empirical tradeoff, not security invalidation. Report it and avoid efficiency claims until measured. |
| R24 | Action/no-action behavior itself leaks private information. | Survive | Action semantics is intentional declassification. Report allowed leakage separately from forbidden excess leakage. |
| R25 | The observer model omits a real timing, cost, collusion, or failure channel. | Fatal | A deployment claim cannot survive an omitted observable channel. Expand the model or reduce the claim to declared projections. |
| R26 | Chance-level AUC is manufactured by pointwise-equal synthetic features. | Pivot | Correct for K6-12. Treat AUC 0.500 only as harness smoke and add implementation-derived matched-action traces. |
| R27 | Timeout or resource exhaustion is silently reported as unrealizable. | Fatal | Preserve `TIMEOUT`, `RESOURCE_LIMIT`, and `Inconclusive`. Any conflation invalidates negative results. |
| R28 | Mutation tests do not justify 100% tamper-resistance. | Pivot | Report only the tested mutation classes and parser bounds; add fuzzing and independent corpus mutation. |
| R29 | There is no BLE, OS-scheduling, biosignal, or hardware evidence. | Pivot | Keep K6 software-only. Deployment claims require separate K4/K5 evidence and cannot inherit CI status. |
| R30 | Search never finds a useful plan not already encoded by the authors. | Fatal | For synthesis as the center, preregister nontrivial held-out tasks and show discovery. Otherwise pivot permanently to checker/repair. |
| R31 | A prior system is found with the same action quotient, full trace, utility, and certificate semantics. | Fatal | Withdraw the priority wording and compare as replication/engineering unless a narrower technical distinction remains. |
| R32 | Optional-solver CI is skipped, so solver support is untested in routine builds. | Pivot | Keep solver support experimental until z3/cvc5 jobs run on pinned versions and their candidates pass the independent checker. |

## 6. Why the current result is PIVOT rather than GO

The implementation has crossed the threshold for a coherent artifact:

- one finite security/utility model is used by negative examples, repair, and synthesis candidates;
- solver output is not trusted for acceptance;
- generated runtime inputs exclude private acquisition state;
- certificate, codegen, adapter, CLI, benchmark, and Studio paths are connected;
- the synthetic attack control behaves as designed;
- timeout and bounded-negative outcomes remain distinct.

It has not crossed the threshold for the broader research claim:

- no external-solver scalability grid has been reported;
- no direct comparison with HyperLTL/privacy-synthesis/traffic-shaping tools has been run;
- no held-out nontrivial task demonstrates automatic mechanism discovery;
- no real or implementation-derived matched-action attack dataset has been evaluated;
- no hardware cost validates the objective vector;
- no independent implementation or mechanized checker validates the TCB;
- the literature review is scoped and is not a complete patent search.

## 7. Pivot scope

The next evaluation should preserve the existing implementation and narrow the paper artifact to:

```text
bounded AQRS model
+ explicit action-quotient observer semantics
+ finite product checker and counterexamples
+ typed release-IR repair
+ certificate-linked public-only no_std code generation
+ Noticer integration
```

Small-model synthesis remains a reference backend until it earns a central claim.

Required evidence to upgrade from PIVOT to GO:

| Gate | Required result |
|---|---|
| G1 | Pin z3 and/or cvc5 and run a reproducible state/horizon/observer/fault grid |
| G2 | Complete at least one preregistered nontrivial model at or beyond 12 plant states, 8 machine states, horizon 64, or justify a revised bound before observing results |
| G3 | Show quotient reduction and CEGIS effects using actual backend calls, wall time, candidates, and checker calls |
| G4 | Discover at least one valid held-out transducer not equivalent to a supplied template |
| G5 | Compare against at least one privacy-synthesis baseline and one fixed/DP shaping baseline under a shared observer and utility contract |
| G6 | Replay generated and handwritten runtimes over all finite test vectors and implementation-derived traces |
| G7 | Evaluate claim-only versus full-trace attackers on matched-action traces not created by copying equal features |
| G8 | Calibrate at least bandwidth and latency objectives against a runtime or transport implementation |
| G9 | Fuzz certificate/model parsers and report tested mutation classes without universalizing the result |
| G10 | Re-run prior-work and patent searches immediately before submission and retain qualified wording |

## 8. KILL conditions

The K6 synthesis-centered direction is killed, rather than renamed, if any of these is reproduced:

- the compiler only selects an author-supplied schedule template;
- no independent checker is required to accept solver candidates;
- the action quotient is unused in the checked transition system;
- generated code can directly consume private evidence or acquisition state;
- security passes by suppressing, duplicating, delaying beyond deadline, or inventing actions;
- a mutated or mismatched certificate is accepted for a different model or transducer;
- generated runtime traces differ from accepted certificate traces;
- timeout or resource exhaustion is presented as unrealizability;
- an omitted observer is nevertheless included in the security claim;
- no held-out case demonstrates useful construction beyond handwritten mechanisms.

If synthesis is killed but checker/repair remain sound and useful, those components may continue as
a separate verification artifact. That is a different contribution and must be titled accordingly.

## 9. Current paper-safe statement

> We present QuotientForge, a domain-specific toolchain for bounded Action-Quotient Release
> Synthesis. For a finite model and declared observers, it checks and repairs release transducers,
> preserves explicit action and bounded-fault utility obligations, emits independently rechecked
> certificates, and generates a public-only `no_std` runtime. Current evaluation establishes
> reproducible artifact behavior on synthetic small models; scalability and deployment privacy
> remain open empirical questions.

This statement survives the present evidence. Stronger synthesis, performance, deployment, or
priority claims do not.

