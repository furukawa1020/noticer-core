use std::collections::BTreeSet;
use std::time::Duration;

use quotient_forge_check::{
    ActionEmission, ActionId, ActionObligation, EnvironmentInput, FieldId, InputId, ObligationId,
    ObligationRef, Observer, ObserverId, PrivateHistoryId, Release, SemanticContract, SemanticId,
};
use quotient_forge_repair::{
    repair, InconclusiveReason, RepairLimits, RepairOperator, RepairOutcome,
};
use quotient_forge_synth::{
    MachineCell, PlantPair, PlantState, PlantTransition, ReleaseMachine, SynthesisProblem,
};

fn limits() -> RepairLimits {
    RepairLimits {
        max_operator_depth: 2,
        max_variants: 1_000,
        max_frontier: 16,
        time_limit: Duration::from_secs(5),
        checker_limits: quotient_forge_check::CheckLimits {
            max_nodes: 10_000,
            max_depth: 16,
            time_limit: Duration::from_secs(5),
        },
    }
}

fn field_problem(field: &str, left: &str, right: &str) -> (SynthesisProblem, ReleaseMachine) {
    let semantic = SemanticId::from("same");
    let field_id = FieldId::from(field);
    let problem = SynthesisProblem {
        horizon: 1,
        machine_symbol_count: 2,
        plant_states: vec![
            PlantState {
                id: 0,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("left"),
            },
            PlantState {
                id: 1,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("right"),
            },
        ],
        plant_transitions: vec![
            PlantTransition {
                from: 0,
                input: 0,
                to: 0,
                machine_symbol: 0,
            },
            PlantTransition {
                from: 1,
                input: 0,
                to: 1,
                machine_symbol: 1,
            },
        ],
        inputs: vec![EnvironmentInput {
            id: InputId::from("tick"),
            public_symbol: "tick".to_owned(),
            fault: None,
        }],
        semantics: vec![SemanticContract {
            id: semantic,
            obligations: Vec::new(),
        }],
        faults: Vec::new(),
        observers: vec![Observer {
            id: ObserverId::from("network"),
            visible_fields: BTreeSet::from([field_id.clone()]),
            observes_actions: false,
        }],
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![
            Release {
                emitted: true,
                fields: [(field_id.clone(), left.to_owned())].into_iter().collect(),
                actions: Vec::new(),
            },
            Release {
                emitted: true,
                fields: [(field_id, right.to_owned())].into_iter().collect(),
                actions: Vec::new(),
            },
        ],
    };
    let machine = ReleaseMachine {
        state_count: 1,
        symbol_count: 2,
        cells: vec![
            MachineCell {
                next_state: 0,
                output: 0,
            },
            MachineCell {
                next_state: 0,
                output: 1,
            },
        ],
    };
    (problem, machine)
}

fn first_point(outcome: RepairOutcome) -> quotient_forge_repair::RepairPoint {
    let RepairOutcome::Repaired(frontier) = outcome else {
        panic!("expected a repaired frontier");
    };
    frontier.points.into_iter().next().unwrap()
}

#[test]
fn fixed_size_repairs_variable_size_observation() {
    let (problem, machine) = field_problem("size", "17", "64");
    let point = first_point(
        repair(
            &problem,
            &machine,
            &[RepairOperator::FixedSize {
                field: "size".to_owned(),
                bytes: 32,
            }],
            limits(),
        )
        .unwrap(),
    );
    assert_eq!(
        point.outputs[0].fields[&FieldId::from("size")],
        "<fixed:32>"
    );
    assert_eq!(point.outputs[0], point.outputs[1]);
}

#[test]
fn public_retry_reconnect_repairs_secret_retry_trace() {
    let (problem, machine) = field_problem("retry", "secret-a", "secret-b");
    let point = first_point(
        repair(
            &problem,
            &machine,
            &[RepairOperator::PublicRetryReconnect {
                retry_field: "retry".to_owned(),
                reconnect_field: "reconnect".to_owned(),
            }],
            limits(),
        )
        .unwrap(),
    );
    assert_eq!(point.outputs[0].fields[&FieldId::from("retry")], "public");
}

#[test]
fn failure_normalization_repairs_failure_leakage() {
    let (problem, machine) = field_problem("failure", "sensor-a", "sensor-b");
    let point = first_point(
        repair(
            &problem,
            &machine,
            &[RepairOperator::FailureNormalization {
                field: "failure".to_owned(),
                normalized: "public-failure".to_owned(),
            }],
            limits(),
        )
        .unwrap(),
    );
    assert_eq!(
        point.outputs[0].fields[&FieldId::from("failure")],
        "public-failure"
    );
}

#[test]
fn release_window_repairs_immediate_release() {
    let semantic = SemanticId::from("delayed-notify");
    let action = Release {
        emitted: true,
        fields: Default::default(),
        actions: vec![ActionEmission {
            obligation: ObligationRef::Authorized(ObligationId::from("permit")),
            action: ActionId::from("notify"),
        }],
    };
    let problem = SynthesisProblem {
        horizon: 2,
        machine_symbol_count: 1,
        plant_states: vec![
            PlantState {
                id: 0,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("left"),
            },
            PlantState {
                id: 1,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("right"),
            },
        ],
        plant_transitions: vec![
            PlantTransition {
                from: 0,
                input: 0,
                to: 0,
                machine_symbol: 0,
            },
            PlantTransition {
                from: 1,
                input: 0,
                to: 1,
                machine_symbol: 0,
            },
        ],
        inputs: vec![EnvironmentInput {
            id: InputId::from("tick"),
            public_symbol: "tick".to_owned(),
            fault: None,
        }],
        semantics: vec![SemanticContract {
            id: semantic,
            obligations: vec![ActionObligation {
                id: ObligationId::from("permit"),
                action: ActionId::from("notify"),
                trigger_slot: 1,
                deadline_slot: 1,
            }],
        }],
        faults: Vec::new(),
        observers: vec![Observer {
            id: ObserverId::from("network"),
            visible_fields: BTreeSet::new(),
            observes_actions: true,
        }],
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![action],
    };
    let source = ReleaseMachine {
        state_count: 1,
        symbol_count: 1,
        cells: vec![MachineCell {
            next_state: 0,
            output: 0,
        }],
    };
    let point = first_point(
        repair(
            &problem,
            &source,
            &[RepairOperator::ReleaseWindow { slots: 1 }],
            limits(),
        )
        .unwrap(),
    );
    assert_eq!(point.machine.state_count, 2);
    assert_eq!(point.distance.added_latency, 1);
    assert_eq!(point.provenance.operators[0].name(), "release_window");
}

#[test]
fn cover_repairs_release_presence_leakage() {
    let (mut problem, machine) = field_problem("unused", "same", "same");
    problem.observers[0].visible_fields.clear();
    problem.outputs[0] = Release::silent();
    problem.outputs[1] = Release::emitted();
    let point =
        first_point(repair(&problem, &machine, &[RepairOperator::Cover], limits()).unwrap());
    assert!(point.outputs.iter().all(|output| output.emitted));
    assert_eq!(point.distance.added_cover_releases, 1);
}

#[test]
fn bounded_pareto_frontier_keeps_non_dominated_repairs() {
    let (problem, machine) = field_problem("leak", "0", "1");
    let operators = [
        RepairOperator::Cutoff {
            field: "leak".to_owned(),
            max_bytes: 0,
        },
        RepairOperator::Bucket {
            field: "leak".to_owned(),
            width: 10,
        },
    ];
    let RepairOutcome::Repaired(frontier) =
        repair(&problem, &machine, &operators, limits()).unwrap()
    else {
        panic!("expected a frontier");
    };
    assert_eq!(frontier.points.len(), 2);
    assert!(!frontier.truncated);
    assert!(frontier.points.iter().all(|point| point
        .provenance
        .source
        .as_bytes()
        .iter()
        .any(|byte| *byte != 0)));
    assert!(frontier
        .points
        .iter()
        .all(|point| !point.provenance.operators.is_empty()));

    let truncated_limits = RepairLimits {
        max_frontier: 1,
        ..limits()
    };
    let RepairOutcome::Repaired(truncated) =
        repair(&problem, &machine, &operators, truncated_limits).unwrap()
    else {
        panic!("expected a bounded frontier");
    };
    assert_eq!(truncated.points.len(), 1);
    assert!(truncated.truncated);
}

#[test]
fn no_operator_and_timeout_are_not_success() {
    let (problem, machine) = field_problem("leak", "a", "b");
    assert!(matches!(
        repair(&problem, &machine, &[], limits()).unwrap(),
        RepairOutcome::NoRepair { .. }
    ));
    let timed = RepairLimits {
        time_limit: Duration::ZERO,
        ..limits()
    };
    assert!(matches!(
        repair(
            &problem,
            &machine,
            &[RepairOperator::Cutoff {
                field: "leak".to_owned(),
                max_bytes: 0,
            }],
            timed
        )
        .unwrap(),
        RepairOutcome::Inconclusive {
            reason: InconclusiveReason::TimeLimit { .. },
            ..
        }
    ));
}

#[test]
fn all_typed_operator_names_are_stable() {
    let operators = [
        RepairOperator::Cutoff {
            field: "a".to_owned(),
            max_bytes: 1,
        },
        RepairOperator::Bucket {
            field: "b".to_owned(),
            width: 1,
        },
        RepairOperator::FixedSize {
            field: "c".to_owned(),
            bytes: 1,
        },
        RepairOperator::Cover,
        RepairOperator::FailureNormalization {
            field: "d".to_owned(),
            normalized: "x".to_owned(),
        },
        RepairOperator::PublicRetryReconnect {
            retry_field: "e".to_owned(),
            reconnect_field: "f".to_owned(),
        },
        RepairOperator::ServiceSeparation {
            service_field: "g".to_owned(),
        },
        RepairOperator::ReleaseWindow { slots: 1 },
    ];
    assert_eq!(
        operators.map(|operator| operator.name()),
        [
            "cutoff",
            "bucket",
            "fixed_size",
            "cover",
            "failure_normalization",
            "public_retry_reconnect",
            "service_separation",
            "release_window",
        ]
    );
}
