use quotient_forge_synth::preservation::{
    check_quotient_preservation, FaultTransition, ObserverEvent, PreservationError,
    PreservationLimits, PreservationObligation, PreservationState, PreservationStatus,
};
use quotient_forge_synth::quotient::{
    build_quotient_partition, derive_action_equivalence, ActionSemanticAtom, ActionSemantics,
    QuotientPartition, QuotientState,
};

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn semantics(action: u8) -> ActionSemantics {
    ActionSemantics::new(vec![
        ActionSemanticAtom::new(sha256(1), sha256(action)).unwrap(),
        ActionSemanticAtom::new(sha256(2), sha256(action.saturating_add(1))).unwrap(),
    ])
    .unwrap()
}

fn partition() -> QuotientPartition {
    let states = vec![
        QuotientState::new(0, "private-a", semantics(20)).unwrap(),
        QuotientState::new(1, "private-b", semantics(20)).unwrap(),
        QuotientState::new(2, "private-c", semantics(40)).unwrap(),
        QuotientState::new(3, "private-d", semantics(40)).unwrap(),
    ];
    let relation = derive_action_equivalence(&states).unwrap();
    build_quotient_partition(sha256(240), &states, &relation).unwrap()
}

fn observer(value: u8) -> Vec<ObserverEvent> {
    vec![
        ObserverEvent::new(sha256(10), sha256(value)).unwrap(),
        ObserverEvent::new(sha256(11), sha256(value.saturating_add(1))).unwrap(),
    ]
}

fn state(source: u32, observer_value: u8, utility: u8, fault_target: u32) -> PreservationState {
    PreservationState::new(
        source,
        observer(observer_value),
        vec![sha256(utility)],
        vec![FaultTransition::new(sha256(50), fault_target, sha256(51)).unwrap()],
    )
    .unwrap()
}

fn limits(max_state_pairs: u64) -> PreservationLimits {
    PreservationLimits { max_state_pairs }
}

#[test]
fn all_three_obligations_pass_and_fault_targets_normalize_to_classes() {
    let partition = partition();
    let states = vec![
        state(0, 20, 30, 2),
        state(1, 20, 30, 3),
        state(2, 40, 60, 0),
        state(3, 40, 60, 1),
    ];
    let check = check_quotient_preservation(sha256(240), &partition, &states, &limits(8)).unwrap();

    assert_eq!(check.artifact.overall_status, PreservationStatus::Pass);
    assert!(check.artifact.reduction_enabled);
    assert_eq!(check.artifact.required_state_pairs, 2);
    assert_eq!(check.artifact.checked_state_pairs, 2);
    assert!(check
        .artifact
        .obligation_results
        .iter()
        .all(|result| result.status == PreservationStatus::Pass));
    check.artifact.validate().unwrap();
}

#[test]
fn each_obligation_has_a_typed_minimal_witness_and_disables_reduction() {
    let partition = partition();
    let states = vec![
        state(0, 20, 30, 2),
        state(1, 21, 31, 0),
        state(2, 40, 60, 0),
        state(3, 40, 60, 1),
    ];
    let check = check_quotient_preservation(sha256(240), &partition, &states, &limits(8)).unwrap();

    assert_eq!(check.artifact.overall_status, PreservationStatus::Fail);
    assert!(!check.artifact.reduction_enabled);
    for obligation in PreservationObligation::ALL {
        let result = check
            .artifact
            .obligation_results
            .iter()
            .find(|result| result.obligation == obligation)
            .unwrap();
        assert_eq!(result.status, PreservationStatus::Fail);
        assert_eq!(result.witness.as_ref().unwrap().obligation, obligation);
        assert_eq!(check.source_pair_for(obligation), Some((0, 1)));
    }
    let json = serde_json::to_string(&check.artifact).unwrap();
    assert!(!json.contains("private-a"));
    assert!(!json.contains("private-b"));
    assert!(!check.artifact.source_indices_included);
}

#[test]
fn pair_limit_is_inconclusive_and_never_enables_reduction() {
    let partition = partition();
    let states = vec![
        state(0, 20, 30, 2),
        state(1, 20, 30, 3),
        state(2, 40, 60, 0),
        state(3, 40, 60, 1),
    ];
    let check = check_quotient_preservation(sha256(240), &partition, &states, &limits(1)).unwrap();
    assert_eq!(
        check.artifact.overall_status,
        PreservationStatus::Inconclusive
    );
    assert!(!check.artifact.reduction_enabled);
    assert_eq!(check.artifact.checked_state_pairs, 0);
    assert!(check
        .artifact
        .obligation_results
        .iter()
        .all(|result| result.status == PreservationStatus::Inconclusive));
}

#[test]
fn missing_state_data_and_unknown_fault_targets_fail_closed() {
    let partition = partition();
    let missing = vec![
        state(0, 20, 30, 2),
        state(1, 20, 30, 3),
        state(2, 40, 60, 0),
    ];
    assert_eq!(
        check_quotient_preservation(sha256(240), &partition, &missing, &limits(8)).unwrap_err(),
        PreservationError::MissingStateData
    );
    let unknown_target = vec![
        state(0, 20, 30, 99),
        state(1, 20, 30, 3),
        state(2, 40, 60, 0),
        state(3, 40, 60, 1),
    ];
    assert_eq!(
        check_quotient_preservation(sha256(240), &partition, &unknown_target, &limits(8))
            .unwrap_err(),
        PreservationError::UnknownFaultTarget
    );
}

#[test]
fn state_input_order_does_not_change_the_public_artifact() {
    let partition = partition();
    let mut states = vec![
        state(0, 20, 30, 2),
        state(1, 20, 30, 3),
        state(2, 40, 60, 0),
        state(3, 40, 60, 1),
    ];
    let first = check_quotient_preservation(sha256(240), &partition, &states, &limits(8)).unwrap();
    states.reverse();
    let second = check_quotient_preservation(sha256(240), &partition, &states, &limits(8)).unwrap();
    assert_eq!(first.artifact, second.artifact);
}
