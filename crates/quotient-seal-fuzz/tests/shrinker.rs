use quotient_seal_fuzz::{
    shrink_counterexample, AdaptiveContextBounds, AdaptiveHostAction, AdaptiveHostProgram,
    FuzzCounterexample, FuzzViolationKind, IndependentReplayChecker, ReplayResult, ShrinkBounds,
    ShrinkError, ShrinkInconclusiveReason, ShrinkPhase, ShrinkVerdict,
};

#[derive(Clone, Copy)]
enum CheckerMode {
    Rule,
    NoViolation,
    Unsupported,
    ResourceBound,
}

struct SyntheticChecker {
    mode: CheckerMode,
    witness: u8,
}

impl IndependentReplayChecker for SyntheticChecker {
    fn replay(&mut self, program: &AdaptiveHostProgram) -> ReplayResult {
        match self.mode {
            CheckerMode::Unsupported => ReplayResult::Unsupported { code: 71 },
            CheckerMode::ResourceBound => ReplayResult::ResourceBound { code: 81 },
            CheckerMode::NoViolation => ReplayResult::NoViolation,
            CheckerMode::Rule => {
                let malformed = program
                    .actions
                    .iter()
                    .any(|action| matches!(action, AdaptiveHostAction::Malformed { .. }));
                let service_switch = program
                    .actions
                    .iter()
                    .any(|action| matches!(action, AdaptiveHostAction::ServiceSwitch { .. }));
                if malformed && service_switch {
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
    }
}

fn program() -> AdaptiveHostProgram {
    AdaptiveHostProgram::build(
        0x5eed,
        AdaptiveContextBounds {
            max_steps: 16,
            max_service_alias: 4,
            max_repeat: 4,
            max_faults: 4,
            max_public_events: 64,
        },
        vec![
            AdaptiveHostAction::Tick { public_slot: 99 },
            AdaptiveHostAction::Malformed { payload_tag: 77 },
            AdaptiveHostAction::Handoff { service_alias: 2 },
            AdaptiveHostAction::ServiceSwitch { from: 2, to: 3 },
            AdaptiveHostAction::Repeat { count: 3 },
        ],
    )
    .unwrap()
}

fn expected() -> FuzzCounterexample {
    FuzzCounterexample {
        step_index: 3,
        kind: FuzzViolationKind::ObserverTraceDivergence,
        code: 41,
        action: AdaptiveHostAction::ServiceSwitch { from: 2, to: 3 },
        public_witness_sha256: [0xa5; 32],
    }
}

fn bounds(max_attempts: u32) -> ShrinkBounds {
    ShrinkBounds {
        max_actions: 16,
        max_replay_attempts: max_attempts,
    }
}

fn rule_checker(witness: u8) -> SyntheticChecker {
    SyntheticChecker {
        mode: CheckerMode::Rule,
        witness,
    }
}

#[test]
fn deletion_input_and_context_reduction_produce_one_minimal_program() {
    let original = program();
    let mut primary = rule_checker(1);
    let mut secondary = rule_checker(2);
    let report = shrink_counterexample(
        &original,
        expected(),
        bounds(128),
        &mut primary,
        &mut secondary,
    )
    .unwrap();
    assert_eq!(
        report.verdict,
        ShrinkVerdict::Reproduced { one_minimal: true }
    );
    assert_eq!(
        report.minimized_program.actions,
        vec![
            AdaptiveHostAction::Malformed { payload_tag: 0 },
            AdaptiveHostAction::ServiceSwitch { from: 0, to: 1 },
        ]
    );
    assert!(report
        .attempts
        .iter()
        .any(|attempt| attempt.phase == ShrinkPhase::CallDeletion));
    assert!(report
        .attempts
        .iter()
        .any(|attempt| attempt.phase == ShrinkPhase::InputSimplification));
    assert!(report
        .attempts
        .iter()
        .any(|attempt| attempt.phase == ShrinkPhase::ContextReduction));
    assert_eq!(report.evidence_origin, "INJECTED_TEST_FIXTURE");
    assert_eq!(report.hardware_status, "NOT_VERIFIED");
}

#[test]
fn same_program_and_checkers_are_byte_reproducible() {
    let original = program();
    let mut left_primary = rule_checker(1);
    let mut left_secondary = rule_checker(2);
    let left = shrink_counterexample(
        &original,
        expected(),
        bounds(128),
        &mut left_primary,
        &mut left_secondary,
    )
    .unwrap();
    let mut right_primary = rule_checker(1);
    let mut right_secondary = rule_checker(2);
    let right = shrink_counterexample(
        &original,
        expected(),
        bounds(128),
        &mut right_primary,
        &mut right_secondary,
    )
    .unwrap();
    assert_eq!(
        left.canonical_json().unwrap(),
        right.canonical_json().unwrap()
    );
}

#[test]
fn checker_disagreement_is_inconclusive() {
    let original = program();
    let mut primary = rule_checker(1);
    let mut secondary = SyntheticChecker {
        mode: CheckerMode::NoViolation,
        witness: 2,
    };
    let report = shrink_counterexample(
        &original,
        expected(),
        bounds(128),
        &mut primary,
        &mut secondary,
    )
    .unwrap();
    assert_eq!(
        report.verdict,
        ShrinkVerdict::Inconclusive {
            reason: ShrinkInconclusiveReason::CheckerDisagreement { attempt_index: 0 }
        }
    );
}

#[test]
fn replay_bound_unsupported_and_resource_bound_are_inconclusive() {
    let original = program();
    let mut bounded_primary = rule_checker(1);
    let mut bounded_secondary = rule_checker(2);
    let bounded = shrink_counterexample(
        &original,
        expected(),
        bounds(1),
        &mut bounded_primary,
        &mut bounded_secondary,
    )
    .unwrap();
    assert_eq!(
        bounded.verdict,
        ShrinkVerdict::Inconclusive {
            reason: ShrinkInconclusiveReason::ReplayBound
        }
    );

    let mut unsupported_primary = SyntheticChecker {
        mode: CheckerMode::Unsupported,
        witness: 1,
    };
    let mut unsupported_secondary = rule_checker(2);
    let unsupported = shrink_counterexample(
        &original,
        expected(),
        bounds(128),
        &mut unsupported_primary,
        &mut unsupported_secondary,
    )
    .unwrap();
    assert!(matches!(
        unsupported.verdict,
        ShrinkVerdict::Inconclusive {
            reason: ShrinkInconclusiveReason::Unsupported { code: 71, .. }
        }
    ));

    let mut resource_primary = rule_checker(1);
    let mut resource_secondary = SyntheticChecker {
        mode: CheckerMode::ResourceBound,
        witness: 2,
    };
    let resource = shrink_counterexample(
        &original,
        expected(),
        bounds(128),
        &mut resource_primary,
        &mut resource_secondary,
    )
    .unwrap();
    assert!(matches!(
        resource.verdict,
        ShrinkVerdict::Inconclusive {
            reason: ShrinkInconclusiveReason::ResourceBound { code: 81, .. }
        }
    ));
}

#[test]
fn report_tamper_fails_full_recomputation() {
    let original = program();
    let mut primary = rule_checker(1);
    let mut secondary = rule_checker(2);
    let mut report = shrink_counterexample(
        &original,
        expected(),
        bounds(128),
        &mut primary,
        &mut secondary,
    )
    .unwrap();
    report.artifact_sha256[0] ^= 0xff;
    assert_eq!(
        report.validate().unwrap_err(),
        ShrinkError::ArtifactMismatch
    );
}
