use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use quotient_forge_check::{
    ActionEmission, ActionId, ActionObligation, CheckLimits, EnvironmentInput, FaultInput,
    FaultInputId, FieldId, InputId, ObligationId, ObligationRef, Observer, ObserverId,
    PrivateHistoryId, RecoveryRequirement, Release, SemanticContract, SemanticId,
};
use quotient_forge_solver::{
    compile_bounded_safety_game, compile_quantifier_order_mutant_fixture, evaluate_qbf_truth,
    QbfCompileError, QbfCompileLimits, QuantifierKind, QuantifierLayout, QBF_SEMANTICS_SCHEMA_V1,
};
use quotient_forge_synth::{
    find_feasible, PlantPair, PlantState, PlantTransition, SynthesisLimits, SynthesisOutcome,
    SynthesisProblem,
};

fn limits() -> QbfCompileLimits {
    QbfCompileLimits {
        max_machine_states: 1,
        max_table_assignments: 64,
        max_candidates: 16,
        max_scenarios: 16,
        seed: 23,
    }
}

fn exhaustive_truth(problem: &SynthesisProblem) -> bool {
    let outcome = find_feasible(
        problem,
        SynthesisLimits {
            max_states: 1,
            max_candidates: 64,
            time_limit: Duration::from_secs(5),
            checker_limits: CheckLimits::default(),
            seed: 23,
        },
    )
    .expect("the independent exhaustive backend must run");
    matches!(outcome, SynthesisOutcome::Realizable(_))
}

#[test]
fn qbf_truth_matches_independent_exhaustive_semantics() {
    for (problem, expected) in [(fixture(false), true), (fixture(true), false)] {
        let compilation = compile_bounded_safety_game(&problem, limits()).expect("compile QBF");
        let qbf_truth = evaluate_qbf_truth(&compilation.spec, 24).expect("evaluate tiny QBF");
        assert_eq!(qbf_truth, expected);
        assert_eq!(qbf_truth, exhaustive_truth(&problem));
        assert_eq!(
            compilation.metadata.quantifier_layout,
            QuantifierLayout::MachineBeforeTrace
        );
        assert_eq!(compilation.metadata.schema_version, QBF_SEMANTICS_SCHEMA_V1);
        assert!(!compilation.metadata.non_production_mutant);
        assert_eq!(compilation.metadata.bounds.machine_states, 1);
        assert_eq!(compilation.metadata.bounds.horizon, 1);
        assert_eq!(
            compilation
                .qdimacs
                .metadata
                .quantifier_blocks
                .iter()
                .map(|block| block.kind)
                .collect::<Vec<_>>(),
            vec![
                QuantifierKind::Existential,
                QuantifierKind::Universal,
                QuantifierKind::Existential
            ]
        );
    }
}

#[test]
fn quantifier_order_mutant_is_detected_by_conflicting_scenarios() {
    let problem = fixture(true);
    let production = compile_bounded_safety_game(&problem, limits()).expect("production QBF");
    let mutant = compile_quantifier_order_mutant_fixture(&problem, limits()).expect("mutant QBF");

    assert!(!evaluate_qbf_truth(&production.spec, 24).expect("production truth"));
    assert!(evaluate_qbf_truth(&mutant.spec, 24).expect("mutant truth"));
    assert_eq!(
        mutant.metadata.quantifier_layout,
        QuantifierLayout::MachineAfterTraceMutant
    );
    assert!(mutant.metadata.non_production_mutant);
}

#[test]
fn compilation_is_canonical_and_records_hard_bounds() {
    let problem = fixture(false);
    let first = compile_bounded_safety_game(&problem, limits()).expect("first compile");
    let second = compile_bounded_safety_game(&problem, limits()).expect("second compile");

    assert_eq!(first.qdimacs.document, second.qdimacs.document);
    assert_eq!(first.metadata, second.metadata);
    assert_eq!(first.metadata.bounds.plant_states, 4);
    assert_eq!(first.metadata.bounds.machine_symbols, 2);
    assert_eq!(first.metadata.bounds.outputs, 2);
    assert_eq!(first.metadata.bounds.scenarios, 1);
    assert!(first
        .metadata
        .hard_obligations
        .contains(&"complete_observer_trace_equality".to_owned()));
    assert!(first
        .metadata
        .hard_obligations
        .contains(&"fault_recovery".to_owned()));
    assert!(first
        .metadata_json_bytes()
        .expect("metadata JSON")
        .ends_with(b"\n"));

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/quotient_forge_qbf_semantics_v1.schema.json"
    ))
    .expect("schema is JSON");
    assert_eq!(schema["$id"], QBF_SEMANTICS_SCHEMA_V1);
}

#[test]
fn vacuous_premise_and_empty_trace_domain_fail_closed() {
    let mut no_pairs = fixture(false);
    no_pairs.initial_pairs.clear();
    assert!(matches!(
        compile_bounded_safety_game(&no_pairs, limits()),
        Err(QbfCompileError::VacuousActionEquivalence)
    ));

    let mut no_inputs = fixture(false);
    no_inputs.inputs.clear();
    no_inputs.plant_transitions.clear();
    assert!(matches!(
        compile_bounded_safety_game(&no_inputs, limits()),
        Err(QbfCompileError::EmptyTraceDomain)
    ));
}

fn fixture(include_conflicting_quiet_pair: bool) -> SynthesisProblem {
    let deliver = ActionObligation {
        id: ObligationId::from("deliver"),
        action: ActionId::from("notify"),
        trigger_slot: 0,
        deadline_slot: 0,
    };
    let retry = ActionObligation {
        id: ObligationId::from("retry"),
        action: ActionId::from("retry"),
        trigger_slot: 0,
        deadline_slot: 0,
    };
    let action_semantic = SemanticId::from("action");
    let quiet_semantic = SemanticId::from("quiet");
    let fault = FaultInputId::from("link_loss");
    let retry_emission = ActionEmission {
        obligation: ObligationRef::Authorized(ObligationId::from("retry")),
        action: ActionId::from("retry"),
    };
    let recovery_emission = ActionEmission {
        obligation: ObligationRef::Recovery {
            fault: fault.clone(),
            triggered_at: 0,
        },
        action: ActionId::from("reconnect"),
    };
    let mut common_fields = BTreeMap::new();
    common_fields.insert(FieldId::from("retry_count"), "1".to_owned());
    common_fields.insert(FieldId::from("reconnect"), "normalized".to_owned());
    let common_release = Release {
        emitted: true,
        fields: common_fields.clone(),
        actions: vec![retry_emission.clone(), recovery_emission.clone()],
    };
    let action_release = Release {
        emitted: true,
        fields: common_fields,
        actions: vec![
            ActionEmission {
                obligation: ObligationRef::Authorized(ObligationId::from("deliver")),
                action: ActionId::from("notify"),
            },
            retry_emission,
            recovery_emission,
        ],
    };

    let mut initial_pairs = vec![PlantPair { left: 0, right: 1 }];
    if include_conflicting_quiet_pair {
        initial_pairs.push(PlantPair { left: 2, right: 3 });
    }

    SynthesisProblem {
        horizon: 1,
        machine_symbol_count: 2,
        plant_states: vec![
            PlantState {
                id: 0,
                action_semantics: action_semantic.clone(),
                private_history: PrivateHistoryId::from("action-left"),
            },
            PlantState {
                id: 1,
                action_semantics: action_semantic.clone(),
                private_history: PrivateHistoryId::from("action-right"),
            },
            PlantState {
                id: 2,
                action_semantics: quiet_semantic.clone(),
                private_history: PrivateHistoryId::from("quiet-left"),
            },
            PlantState {
                id: 3,
                action_semantics: quiet_semantic.clone(),
                private_history: PrivateHistoryId::from("quiet-right"),
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
            PlantTransition {
                from: 2,
                input: 0,
                to: 2,
                machine_symbol: 0,
            },
            PlantTransition {
                from: 3,
                input: 0,
                to: 3,
                machine_symbol: 1,
            },
        ],
        inputs: vec![EnvironmentInput {
            id: InputId::from("tick-with-link-loss"),
            public_symbol: "tick".to_owned(),
            fault: Some(fault.clone()),
        }],
        semantics: vec![
            SemanticContract {
                id: action_semantic,
                obligations: vec![deliver, retry.clone()],
            },
            SemanticContract {
                id: quiet_semantic,
                obligations: vec![retry],
            },
        ],
        faults: vec![FaultInput {
            id: fault,
            recovery: Some(RecoveryRequirement {
                action: ActionId::from("reconnect"),
                deadline_after_slots: 0,
            }),
        }],
        observers: vec![Observer {
            id: ObserverId::from("network"),
            visible_fields: BTreeSet::from([
                FieldId::from("retry_count"),
                FieldId::from("reconnect"),
            ]),
            observes_actions: true,
        }],
        initial_pairs,
        outputs: vec![common_release, action_release],
    }
}
