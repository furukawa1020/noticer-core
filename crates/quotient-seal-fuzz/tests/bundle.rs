use quotient_seal_fuzz::{
    apply_public_feedback, run_adaptive_fuzz, shrink_counterexample, AdaptiveActionClass,
    AdaptiveContextBounds, AdaptiveContextState, AdaptiveFuzzBudget, AdaptiveFuzzConfig,
    AdaptiveFuzzReport, AdaptiveFuzzReproductionBundle, AdaptiveHostAction, AdaptiveHostProgram,
    BundleError, BundleInconclusiveReason, BundleVerdict, CorpusBounds, CorpusEntry,
    CoverageFeedback, DeterministicCorpus, FuzzInconclusiveReason, FuzzVerdict, FuzzViolationKind,
    IndependentReplayChecker, PublicCoverageSnapshot, PublicFuzzInput, PublicFuzzTarget,
    PublicObserverDivergence, PublicTargetStatus, PublicTargetStep, ReplayResult, ShrinkBounds,
    ShrinkInconclusiveReason,
};

#[derive(Clone, Copy)]
enum TargetMode {
    Vulnerable,
    Safe,
    Slow,
}

struct SyntheticTarget {
    mode: TargetMode,
}

impl PublicFuzzTarget for SyntheticTarget {
    fn execute(&mut self, input: PublicFuzzInput) -> PublicTargetStep {
        let class = AdaptiveActionClass::of(input.action);
        let marker = class.code() + 1;
        let status = if matches!(self.mode, TargetMode::Vulnerable)
            && class == AdaptiveActionClass::ServiceSwitch
        {
            PublicTargetStatus::Counterexample {
                kind: FuzzViolationKind::ObserverTraceDivergence,
                code: 41,
                public_witness_sha256: [0xa5; 32],
            }
        } else {
            PublicTargetStatus::Continue
        };
        PublicTargetStep {
            observation: quotient_seal_fuzz::AdaptivePublicObservation {
                event_count: 1,
                action_count: 1,
                trap_count: u32::from(class == AdaptiveActionClass::Malformed),
                host_call_count: 1,
                resource_units: 2,
                public_trace_sha256: [marker; 32],
            },
            coverage: PublicCoverageSnapshot {
                target_block: u32::from(marker),
                product_source_state: input.step,
                product_target_state: u32::from(marker),
                observer_divergence: (class == AdaptiveActionClass::ServiceSwitch).then_some(
                    PublicObserverDivergence {
                        observer_profile: 1,
                        divergence_code: 3,
                        public_trace_sha256: [marker; 32],
                    },
                ),
                utility_violation: None,
            },
            logical_time_units: if matches!(self.mode, TargetMode::Slow) {
                2
            } else {
                1
            },
            status,
        }
    }
}

#[derive(Clone, Copy)]
enum CheckerMode {
    Reproduce,
    NoViolation,
}

struct SwitchChecker {
    mode: CheckerMode,
    witness: u8,
}

impl IndependentReplayChecker for SwitchChecker {
    fn replay(&mut self, program: &AdaptiveHostProgram) -> ReplayResult {
        if matches!(self.mode, CheckerMode::Reproduce)
            && program
                .actions
                .iter()
                .any(|action| matches!(action, AdaptiveHostAction::ServiceSwitch { .. }))
        {
            ReplayResult::Violation {
                kind: FuzzViolationKind::ObserverTraceDivergence,
                code: 41,
                public_witness_sha256: [self.witness; 32],
            }
        } else {
            ReplayResult::NoViolation
        }
    }
}

fn config(max_states: u32, max_time: u64) -> AdaptiveFuzzConfig {
    AdaptiveFuzzConfig {
        seed: 0x5eed,
        context_bounds: AdaptiveContextBounds {
            max_steps: 16,
            max_service_alias: 4,
            max_repeat: 4,
            max_faults: 4,
            max_public_events: 64,
        },
        corpus_bounds: CorpusBounds {
            max_entries: 16,
            max_coverage_points: 256,
            max_actions_per_entry: 16,
        },
        budget: AdaptiveFuzzBudget {
            max_steps: 10,
            max_states,
            max_logical_time_units: max_time,
        },
    }
}

fn reconstruct(
    report: &AdaptiveFuzzReport,
    mode: TargetMode,
) -> (
    Option<AdaptiveHostProgram>,
    Vec<CoverageFeedback>,
    DeterministicCorpus,
) {
    let mut target = SyntheticTarget { mode };
    let mut state = AdaptiveContextState::initial(report.context_bounds).unwrap();
    let mut corpus = DeterministicCorpus::new(report.seed, report.corpus_bounds).unwrap();
    let mut actions = Vec::new();
    let mut feedbacks = Vec::new();
    for step in &report.steps {
        let output = target.execute(PublicFuzzInput {
            step: step.index,
            state,
            action: step.action,
        });
        let transition = apply_public_feedback(state, step.action, output.observation).unwrap();
        let feedback =
            CoverageFeedback::from_public_transition(&transition, output.coverage).unwrap();
        actions.push(step.action);
        let program =
            AdaptiveHostProgram::build(report.seed, report.context_bounds, actions.clone())
                .unwrap();
        corpus
            .insert(
                CorpusEntry::build(
                    report.seed,
                    program.artifact_sha256,
                    actions.len() as u32,
                    feedback.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        feedbacks.push(feedback);
        state = transition.after;
    }
    let program = (!actions.is_empty())
        .then(|| AdaptiveHostProgram::build(report.seed, report.context_bounds, actions).unwrap());
    (program, feedbacks, corpus)
}

fn counterexample_bundle(disagree: bool) -> AdaptiveFuzzReproductionBundle {
    let mut target = SyntheticTarget {
        mode: TargetMode::Vulnerable,
    };
    let report = run_adaptive_fuzz(config(16, 100), &mut target).unwrap();
    let FuzzVerdict::Counterexample { counterexample } = report.verdict else {
        panic!("fixture must produce a counterexample");
    };
    let (program, feedback, corpus) = reconstruct(&report, TargetMode::Vulnerable);
    let program_ref = program.as_ref().unwrap();
    let mut primary = SwitchChecker {
        mode: CheckerMode::Reproduce,
        witness: 1,
    };
    let mut secondary = SwitchChecker {
        mode: if disagree {
            CheckerMode::NoViolation
        } else {
            CheckerMode::Reproduce
        },
        witness: 2,
    };
    let shrink = shrink_counterexample(
        program_ref,
        counterexample,
        ShrinkBounds {
            max_actions: 16,
            max_replay_attempts: 128,
        },
        &mut primary,
        &mut secondary,
    )
    .unwrap();
    AdaptiveFuzzReproductionBundle::build(report, program, feedback, corpus, Some(shrink)).unwrap()
}

#[test]
fn counterexample_bundle_cross_links_every_artifact() {
    let bundle = counterexample_bundle(false);
    assert!(matches!(
        bundle.verdict,
        BundleVerdict::CounterexampleReproduced {
            kind: FuzzViolationKind::ObserverTraceDivergence,
            code: 41,
            one_minimal: true
        }
    ));
    assert_eq!(
        bundle.coverage_feedback.len(),
        bundle.fuzz_report.steps.len()
    );
    assert_eq!(bundle.evidence_origin, "INJECTED_TEST_FIXTURE");
    assert_eq!(bundle.hardware_status, "NOT_VERIFIED");
    bundle.validate().unwrap();
}

#[test]
fn canonical_bundle_round_trip_is_byte_reproducible() {
    let bundle = counterexample_bundle(false);
    let encoded = bundle.canonical_json().unwrap();
    let decoded = AdaptiveFuzzReproductionBundle::decode_json(&encoded).unwrap();
    assert_eq!(decoded, bundle);
    assert_eq!(decoded.canonical_json().unwrap(), encoded);

    let mut non_canonical = encoded;
    non_canonical.push(b' ');
    assert_eq!(
        AdaptiveFuzzReproductionBundle::decode_json(&non_canonical).unwrap_err(),
        BundleError::NonCanonical
    );
}

#[test]
fn mismatched_coverage_is_rejected() {
    let bundle = counterexample_bundle(false);
    let mut feedback = bundle.coverage_feedback.clone();
    feedback[0].feedback_sha256[0] ^= 0xff;
    assert_eq!(
        AdaptiveFuzzReproductionBundle::build(
            bundle.fuzz_report,
            bundle.action_program,
            feedback,
            bundle.corpus,
            bundle.shrink_report,
        )
        .unwrap_err(),
        BundleError::EvidenceMismatch
    );
}

#[test]
fn time_and_state_bounds_remain_inconclusive() {
    let mut slow_target = SyntheticTarget {
        mode: TargetMode::Slow,
    };
    let time_report = run_adaptive_fuzz(config(16, 1), &mut slow_target).unwrap();
    let (time_program, time_feedback, time_corpus) = reconstruct(&time_report, TargetMode::Slow);
    let time_bundle = AdaptiveFuzzReproductionBundle::build(
        time_report,
        time_program,
        time_feedback,
        time_corpus,
        None,
    )
    .unwrap();
    assert_eq!(
        time_bundle.verdict,
        BundleVerdict::Inconclusive {
            reason: BundleInconclusiveReason::Fuzz {
                reason: FuzzInconclusiveReason::TimeBudget
            }
        }
    );

    let mut state_target = SyntheticTarget {
        mode: TargetMode::Safe,
    };
    let state_report = run_adaptive_fuzz(config(1, 100), &mut state_target).unwrap();
    let (state_program, state_feedback, state_corpus) =
        reconstruct(&state_report, TargetMode::Safe);
    let state_bundle = AdaptiveFuzzReproductionBundle::build(
        state_report,
        state_program,
        state_feedback,
        state_corpus,
        None,
    )
    .unwrap();
    assert_eq!(
        state_bundle.verdict,
        BundleVerdict::Inconclusive {
            reason: BundleInconclusiveReason::Fuzz {
                reason: FuzzInconclusiveReason::StateBound
            }
        }
    );
}

#[test]
fn shrink_disagreement_remains_inconclusive() {
    let bundle = counterexample_bundle(true);
    assert!(matches!(
        bundle.verdict,
        BundleVerdict::Inconclusive {
            reason: BundleInconclusiveReason::Shrink {
                reason: ShrinkInconclusiveReason::CheckerDisagreement { .. }
            }
        }
    ));
}
