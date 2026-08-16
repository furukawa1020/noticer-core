use std::collections::BTreeSet;
use std::time::Duration;

use quotient_forge_check::{
    check, ActionEmission, ActionId, ActionObligation, CheckOutcome, EnvironmentInput, FieldId,
    InitialPair, InputId, ObligationId, ObligationRef, Observer, ObserverId, PrivateHistoryId,
    Release, SemanticContract, SemanticId,
};
use quotient_forge_synth::{
    blocking_clause_from_counterexample, find_feasible, optimize_cost, InconclusiveReason,
    MachineCell, PlantPair, PlantState, PlantTransition, ReleaseMachine, SynthesisLimits,
    SynthesisOutcome, SynthesisProblem,
};

fn limits(max_states: u32) -> SynthesisLimits {
    SynthesisLimits {
        max_states,
        max_candidates: 100_000,
        time_limit: Duration::from_secs(5),
        checker_limits: quotient_forge_check::CheckLimits {
            max_nodes: 100_000,
            max_depth: 16,
            time_limit: Duration::from_secs(5),
        },
        seed: 0,
    }
}

fn timed_action_problem() -> SynthesisProblem {
    let semantic = SemanticId::from("notify-at-slot-one");
    let input = EnvironmentInput {
        id: InputId::from("tick"),
        public_symbol: "tick".to_owned(),
        fault: None,
    };
    let silent = Release::emitted();
    let action = Release {
        emitted: true,
        fields: Default::default(),
        actions: vec![ActionEmission {
            obligation: ObligationRef::Authorized(ObligationId::from("permit")),
            action: ActionId::from("notify"),
        }],
    };
    SynthesisProblem {
        horizon: 2,
        machine_symbol_count: 1,
        plant_states: vec![
            PlantState {
                id: 0,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("left-private"),
            },
            PlantState {
                id: 1,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("right-private"),
            },
            PlantState {
                id: 2,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("left-private"),
            },
            PlantState {
                id: 3,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("right-private"),
            },
        ],
        plant_transitions: vec![
            PlantTransition {
                from: 0,
                input: 0,
                to: 2,
                machine_symbol: 0,
            },
            PlantTransition {
                from: 1,
                input: 0,
                to: 3,
                machine_symbol: 0,
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
                machine_symbol: 0,
            },
        ],
        inputs: vec![input],
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
        outputs: vec![silent, action],
    }
}

fn optimization_problem() -> SynthesisProblem {
    let semantic = SemanticId::from("no-action");
    SynthesisProblem {
        horizon: 1,
        machine_symbol_count: 2,
        plant_states: vec![
            PlantState {
                id: 0,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("left-private"),
            },
            PlantState {
                id: 1,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("right-private"),
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
            visible_fields: BTreeSet::from([FieldId::from("payload")]),
            observes_actions: false,
        }],
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![
            Release {
                emitted: true,
                fields: [(FieldId::from("payload"), String::new())]
                    .into_iter()
                    .collect(),
                actions: Vec::new(),
            },
            Release {
                emitted: true,
                fields: [(FieldId::from("payload"), "expensive".to_owned())]
                    .into_iter()
                    .collect(),
                actions: Vec::new(),
            },
        ],
    }
}

#[test]
fn minimal_two_state_machine_is_synthesized() {
    let outcome = find_feasible(&timed_action_problem(), limits(2)).unwrap();
    let SynthesisOutcome::Realizable(report) = outcome else {
        panic!("expected a realizable problem");
    };
    assert_eq!(report.machine.state_count, 2);
    assert!(report.minimal_state_count);
    assert!(!report.cost_optimized);
    assert!(report.stats.counterexamples > 0);
    assert!(matches!(
        check(
            &timed_action_problem()
                .lower_candidate(&report.machine)
                .unwrap(),
            limits(2).checker_limits
        )
        .unwrap(),
        CheckOutcome::Verified(_)
    ));
}

#[test]
fn missing_action_alphabet_is_unrealizable() {
    let mut problem = timed_action_problem();
    problem.outputs.truncate(1);
    let outcome = find_feasible(&problem, limits(2)).unwrap();
    let SynthesisOutcome::Unrealizable(report) = outcome else {
        panic!("expected finite unrealizability");
    };
    assert_eq!(report.searched_through_states, 2);
    assert!(report.stats.counterexamples > 0);
}

#[test]
fn candidate_and_time_exhaustion_are_inconclusive() {
    let problem = timed_action_problem();
    let candidate_limited = SynthesisLimits {
        max_candidates: 0,
        ..limits(2)
    };
    assert!(matches!(
        find_feasible(&problem, candidate_limited).unwrap(),
        SynthesisOutcome::Inconclusive {
            reason: InconclusiveReason::CandidateLimit { limit: 0 },
            ..
        }
    ));

    let time_limited = SynthesisLimits {
        time_limit: Duration::ZERO,
        ..limits(2)
    };
    assert!(matches!(
        find_feasible(&problem, time_limited).unwrap(),
        SynthesisOutcome::Inconclusive {
            reason: InconclusiveReason::TimeLimit { .. },
            ..
        }
    ));
}

#[test]
fn counterexample_clause_excludes_its_source_candidate() {
    let problem = timed_action_problem();
    let machine = ReleaseMachine {
        state_count: 1,
        symbol_count: 1,
        cells: vec![MachineCell {
            next_state: 0,
            output: 0,
        }],
    };
    let checker_model = problem.lower_candidate(&machine).unwrap();
    let CheckOutcome::Counterexample(counterexample) =
        check(&checker_model, limits(1).checker_limits).unwrap()
    else {
        panic!("expected a counterexample");
    };
    let blocker = blocking_clause_from_counterexample(&problem, &machine, &counterexample).unwrap();
    assert!(blocker.blocks(&machine));
    assert!(!blocker.assignments.is_empty());
}

#[test]
fn feasibility_and_cost_optimization_are_separate() {
    let problem = optimization_problem();
    let seeded = SynthesisLimits {
        max_states: 1,
        seed: 1,
        ..limits(1)
    };
    let SynthesisOutcome::Realizable(feasible) = find_feasible(&problem, seeded).unwrap() else {
        panic!("expected feasibility result");
    };
    let SynthesisOutcome::Realizable(optimized) = optimize_cost(&problem, seeded).unwrap() else {
        panic!("expected optimized result");
    };
    assert!(!feasible.cost_optimized);
    assert!(optimized.cost_optimized);
    assert!(optimized.cost < feasible.cost);
}

#[test]
fn same_seed_and_canonical_tie_break_are_reproducible() {
    let problem = optimization_problem();
    let seeded = SynthesisLimits {
        max_states: 1,
        seed: 1,
        ..limits(1)
    };
    let first = optimize_cost(&problem, seeded).unwrap();
    let second = optimize_cost(&problem, seeded).unwrap();
    assert_eq!(first, second);
}

#[test]
fn lowered_model_keeps_private_history_out_of_machine_state() {
    let problem = optimization_problem();
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
                output: 0,
            },
        ],
    };
    let model = problem.lower_candidate(&machine).unwrap();
    assert_eq!(
        model.initial_pairs,
        vec![InitialPair {
            left: quotient_forge_check::StateId::from("p0:m0"),
            right: quotient_forge_check::StateId::from("p1:m0"),
        }]
    );
    assert_ne!(
        model.states[0].private_history,
        model.states[1].private_history
    );
}
