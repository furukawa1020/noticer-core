use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use quotient_forge_check::{
    check, ir_input_type_name, ActionEmission, ActionId, ActionObligation, CausalField,
    CheckLimits, CheckOutcome, CheckerModel, CounterexampleKind, EnvironmentInput, FaultInput,
    FaultInputId, FieldId, InconclusiveReason, InitialPair, InputId, ModelError, ObligationId,
    ObligationRef, Observer, ObserverId, PrivateHistoryId, RecoveryRequirement, Release,
    SemanticContract, SemanticId, State, StateId, Transition,
};

fn limits() -> CheckLimits {
    CheckLimits {
        max_nodes: 1_000,
        max_depth: 16,
        time_limit: Duration::from_secs(5),
    }
}

fn field_release(value: &str) -> Release {
    Release {
        emitted: true,
        fields: BTreeMap::from([(FieldId::from("bucket"), value.to_owned())]),
        actions: Vec::new(),
    }
}

fn base_model(left: Release, right: Release, horizon: u32) -> CheckerModel {
    let left_id = StateId::from("left");
    let right_id = StateId::from("right");
    let input = InputId::from("tick");
    CheckerModel {
        horizon,
        states: vec![
            State {
                id: left_id.clone(),
                action_semantics: SemanticId::from("same-action"),
                private_history: PrivateHistoryId::from("private-a"),
            },
            State {
                id: right_id.clone(),
                action_semantics: SemanticId::from("same-action"),
                private_history: PrivateHistoryId::from("private-b"),
            },
        ],
        semantics: vec![SemanticContract {
            id: SemanticId::from("same-action"),
            obligations: Vec::new(),
        }],
        faults: Vec::new(),
        inputs: vec![EnvironmentInput {
            id: input.clone(),
            public_symbol: "public-tick".to_owned(),
            fault: None,
        }],
        transitions: vec![
            Transition {
                from: left_id.clone(),
                input: input.clone(),
                to: left_id.clone(),
                release: left,
            },
            Transition {
                from: right_id.clone(),
                input,
                to: right_id.clone(),
                release: right,
            },
        ],
        observers: vec![Observer {
            id: ObserverId::from("network"),
            visible_fields: BTreeSet::from([FieldId::from("bucket")]),
            observes_actions: true,
        }],
        initial_pairs: vec![InitialPair {
            left: left_id,
            right: right_id,
        }],
    }
}

fn action_release(reference: ObligationRef, action: &str) -> Release {
    Release {
        emitted: true,
        fields: BTreeMap::new(),
        actions: vec![ActionEmission {
            obligation: reference,
            action: ActionId::from(action),
        }],
    }
}

#[test]
fn visible_private_difference_yields_slot_zero_counterexample() {
    let model = base_model(field_release("a"), field_release("b"), 2);
    let CheckOutcome::Counterexample(counterexample) = check(&model, limits()).unwrap() else {
        panic!("expected a counterexample");
    };
    assert_eq!(counterexample.kind, CounterexampleKind::SecurityDivergence);
    assert_eq!(counterexample.slot, 0);
    assert_eq!(counterexample.observer, Some(ObserverId::from("network")));
    assert_eq!(
        counterexample.causal_field,
        Some(CausalField::Field(FieldId::from("bucket")))
    );
    assert_eq!(counterexample.trace.len(), 1);
    assert!(!counterexample.repair_candidates.is_empty());
}

#[test]
fn hidden_difference_is_verified_to_the_declared_bound() {
    let mut model = base_model(field_release("a"), field_release("b"), 2);
    model.observers[0].visible_fields.clear();
    let CheckOutcome::Verified(report) = check(&model, limits()).unwrap() else {
        panic!("expected bounded verification");
    };
    assert_eq!(report.checked_horizon, 2);
    assert_eq!(report.observers, 1);
}

#[test]
fn initial_pair_must_be_action_equivalent_and_private_distinct() {
    let mut model = base_model(field_release("a"), field_release("a"), 1);
    model.states[1].private_history = PrivateHistoryId::from("private-a");
    assert!(matches!(
        check(&model, limits()),
        Err(ModelError::InvalidInitialPair { .. })
    ));

    model.states[1].private_history = PrivateHistoryId::from("private-b");
    model.semantics.push(SemanticContract {
        id: SemanticId::from("different-action"),
        obligations: Vec::new(),
    });
    model.states[1].action_semantics = SemanticId::from("different-action");
    assert!(matches!(
        check(&model, limits()),
        Err(ModelError::InvalidInitialPair { .. })
    ));
}

#[test]
fn authorized_action_exactly_once_passes() {
    let reference = ObligationRef::Authorized(ObligationId::from("permit"));
    let release = action_release(reference, "notify");
    let mut model = base_model(release.clone(), release, 1);
    model.semantics[0].obligations.push(ActionObligation {
        id: ObligationId::from("permit"),
        action: ActionId::from("notify"),
        trigger_slot: 0,
        deadline_slot: 0,
    });
    assert!(matches!(
        check(&model, limits()).unwrap(),
        CheckOutcome::Verified(_)
    ));
}

#[test]
fn unknown_obligation_is_an_unauthorized_action() {
    let reference = ObligationRef::Authorized(ObligationId::from("forged"));
    let release = action_release(reference, "unlock");
    let model = base_model(release.clone(), release, 1);
    let CheckOutcome::Counterexample(counterexample) = check(&model, limits()).unwrap() else {
        panic!("expected an unauthorized action");
    };
    assert!(matches!(
        counterexample.kind,
        CounterexampleKind::UnauthorizedAction { .. }
    ));
    assert_eq!(counterexample.slot, 0);
}

#[test]
fn second_emission_is_reported_as_duplicate() {
    let reference = ObligationRef::Authorized(ObligationId::from("permit"));
    let release = action_release(reference, "notify");
    let mut model = base_model(release.clone(), release, 2);
    model.semantics[0].obligations.push(ActionObligation {
        id: ObligationId::from("permit"),
        action: ActionId::from("notify"),
        trigger_slot: 0,
        deadline_slot: 1,
    });
    let CheckOutcome::Counterexample(counterexample) = check(&model, limits()).unwrap() else {
        panic!("expected a duplicate action");
    };
    assert!(matches!(
        counterexample.kind,
        CounterexampleKind::DuplicateAction { .. }
    ));
    assert_eq!(counterexample.slot, 1);
    assert_eq!(counterexample.trace.len(), 2);
}

#[test]
fn missing_authorized_action_reports_deadline() {
    let release = Release::emitted();
    let mut model = base_model(release.clone(), release, 1);
    model.semantics[0].obligations.push(ActionObligation {
        id: ObligationId::from("permit"),
        action: ActionId::from("notify"),
        trigger_slot: 0,
        deadline_slot: 0,
    });
    let CheckOutcome::Counterexample(counterexample) = check(&model, limits()).unwrap() else {
        panic!("expected a missed deadline");
    };
    assert!(matches!(
        counterexample.kind,
        CounterexampleKind::MissedDeadline { .. }
    ));
}

#[test]
fn missing_same_slot_recovery_reports_recoverable_fault() {
    let release = Release::emitted();
    let mut model = base_model(release.clone(), release, 1);
    let fault_id = FaultInputId::from("recoverable-link-loss");
    model.faults.push(FaultInput {
        id: fault_id.clone(),
        recovery: Some(RecoveryRequirement {
            action: ActionId::from("safe-fallback"),
            deadline_after_slots: 0,
        }),
    });
    model.inputs[0].fault = Some(fault_id);
    let CheckOutcome::Counterexample(counterexample) = check(&model, limits()).unwrap() else {
        panic!("expected a recovery violation");
    };
    assert!(matches!(
        counterexample.kind,
        CounterexampleKind::RecoverableFaultViolation { .. }
    ));
}

#[test]
fn transition_function_must_be_total() {
    let mut model = base_model(field_release("a"), field_release("a"), 1);
    model.transitions.pop();
    assert!(matches!(
        check(&model, limits()),
        Err(ModelError::MissingTransition { .. })
    ));
}

#[test]
fn depth_and_node_limits_are_inconclusive() {
    let model = base_model(field_release("a"), field_release("a"), 2);
    let depth_limited = CheckLimits {
        max_depth: 0,
        ..limits()
    };
    let CheckOutcome::Inconclusive(depth) = check(&model, depth_limited).unwrap() else {
        panic!("depth exhaustion must be inconclusive");
    };
    assert_eq!(depth.reason, InconclusiveReason::DepthLimit { limit: 0 });

    let node_limited = CheckLimits {
        max_nodes: 1,
        ..limits()
    };
    let CheckOutcome::Inconclusive(nodes) = check(&model, node_limited).unwrap() else {
        panic!("node exhaustion must be inconclusive");
    };
    assert_eq!(nodes.reason, InconclusiveReason::NodeLimit { limit: 1 });
}

#[test]
fn checker_is_linked_to_the_canonical_ir_type() {
    assert!(ir_input_type_name().ends_with("quotient_forge_ir::model::CompiledModel"));
}
