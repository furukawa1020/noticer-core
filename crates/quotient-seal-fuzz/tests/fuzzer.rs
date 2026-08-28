use quotient_seal_fuzz::{
    run_adaptive_fuzz, AdaptiveActionClass, AdaptiveContextBounds, AdaptiveFuzzBudget,
    AdaptiveFuzzConfig, CorpusBounds, FuzzError, FuzzInconclusiveReason, FuzzVerdict,
    FuzzViolationKind, PublicCoverageSnapshot, PublicFuzzInput, PublicFuzzTarget,
    PublicObserverDivergence, PublicTargetStatus, PublicTargetStep,
};

#[derive(Clone, Copy)]
enum Mode {
    Safe,
    Vulnerable,
    Unsupported,
    Disagreement,
    Slow,
}

struct SyntheticTarget {
    mode: Mode,
}

impl PublicFuzzTarget for SyntheticTarget {
    fn execute(&mut self, input: PublicFuzzInput) -> PublicTargetStep {
        let class = AdaptiveActionClass::of(input.action);
        let marker = class.code() + 1;
        let status = match self.mode {
            Mode::Vulnerable if class == AdaptiveActionClass::ServiceSwitch => {
                PublicTargetStatus::Counterexample {
                    kind: FuzzViolationKind::ObserverTraceDivergence,
                    code: 41,
                    public_witness_sha256: [0xa5; 32],
                }
            }
            Mode::Unsupported if input.step == 0 => PublicTargetStatus::Unsupported { code: 77 },
            Mode::Disagreement if input.step == 0 => PublicTargetStatus::CheckerDisagreement {
                primary_code: 2,
                secondary_code: 9,
            },
            _ => PublicTargetStatus::Continue,
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
            logical_time_units: if matches!(self.mode, Mode::Slow) {
                2
            } else {
                1
            },
            status,
        }
    }
}

fn config(max_steps: u32, max_states: u32, max_time: u64) -> AdaptiveFuzzConfig {
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
            max_steps,
            max_states,
            max_logical_time_units: max_time,
        },
    }
}

#[test]
fn vulnerable_fixture_yields_typed_counterexample() {
    let mut target = SyntheticTarget {
        mode: Mode::Vulnerable,
    };
    let report = run_adaptive_fuzz(config(10, 16, 100), &mut target).unwrap();
    let FuzzVerdict::Counterexample { counterexample } = report.verdict else {
        panic!("vulnerable fixture must yield a counterexample");
    };
    assert_eq!(
        counterexample.kind,
        FuzzViolationKind::ObserverTraceDivergence
    );
    assert_eq!(counterexample.code, 41);
    assert_eq!(
        AdaptiveActionClass::of(counterexample.action),
        AdaptiveActionClass::ServiceSwitch
    );
    assert_eq!(report.evidence_origin, "INJECTED_TEST_FIXTURE");
    assert_eq!(report.hardware_status, "NOT_VERIFIED");
    report.validate().unwrap();
}

#[test]
fn safe_fixture_exhausts_finite_action_classes() {
    let mut target = SyntheticTarget { mode: Mode::Safe };
    let report = run_adaptive_fuzz(config(10, 16, 100), &mut target).unwrap();
    assert_eq!(report.verdict, FuzzVerdict::Exhausted);
    assert_eq!(report.steps.len(), AdaptiveActionClass::ALL.len());
}

#[test]
fn same_seed_is_byte_reproducible() {
    let mut left_target = SyntheticTarget { mode: Mode::Safe };
    let mut right_target = SyntheticTarget { mode: Mode::Safe };
    let left = run_adaptive_fuzz(config(10, 16, 100), &mut left_target).unwrap();
    let right = run_adaptive_fuzz(config(10, 16, 100), &mut right_target).unwrap();
    assert_eq!(
        left.canonical_json().unwrap(),
        right.canonical_json().unwrap()
    );
    assert_eq!(
        left.public_randomness_sha256,
        right.public_randomness_sha256
    );
}

#[test]
fn resource_limits_are_inconclusive() {
    let mut step_target = SyntheticTarget { mode: Mode::Safe };
    let step = run_adaptive_fuzz(config(3, 16, 100), &mut step_target).unwrap();
    assert_eq!(
        step.verdict,
        FuzzVerdict::Inconclusive {
            reason: FuzzInconclusiveReason::StepBound
        }
    );

    let mut state_target = SyntheticTarget { mode: Mode::Safe };
    let state = run_adaptive_fuzz(config(10, 1, 100), &mut state_target).unwrap();
    assert_eq!(
        state.verdict,
        FuzzVerdict::Inconclusive {
            reason: FuzzInconclusiveReason::StateBound
        }
    );

    let mut time_target = SyntheticTarget { mode: Mode::Slow };
    let time = run_adaptive_fuzz(config(10, 16, 1), &mut time_target).unwrap();
    assert_eq!(
        time.verdict,
        FuzzVerdict::Inconclusive {
            reason: FuzzInconclusiveReason::TimeBudget
        }
    );
}

#[test]
fn unsupported_and_checker_disagreement_are_not_success() {
    let mut unsupported_target = SyntheticTarget {
        mode: Mode::Unsupported,
    };
    let unsupported = run_adaptive_fuzz(config(10, 16, 100), &mut unsupported_target).unwrap();
    assert_eq!(
        unsupported.verdict,
        FuzzVerdict::Inconclusive {
            reason: FuzzInconclusiveReason::Unsupported { code: 77 }
        }
    );

    let mut disagreement_target = SyntheticTarget {
        mode: Mode::Disagreement,
    };
    let disagreement = run_adaptive_fuzz(config(10, 16, 100), &mut disagreement_target).unwrap();
    assert_eq!(
        disagreement.verdict,
        FuzzVerdict::Inconclusive {
            reason: FuzzInconclusiveReason::CheckerDisagreement {
                primary_code: 2,
                secondary_code: 9
            }
        }
    );
}

#[test]
fn report_tamper_fails_full_recomputation() {
    let mut target = SyntheticTarget { mode: Mode::Safe };
    let mut report = run_adaptive_fuzz(config(10, 16, 100), &mut target).unwrap();
    report.public_randomness_sha256[0] ^= 0xff;
    assert_eq!(report.validate().unwrap_err(), FuzzError::ArtifactMismatch);
}
