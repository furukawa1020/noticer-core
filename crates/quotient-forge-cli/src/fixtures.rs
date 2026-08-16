use std::collections::BTreeSet;

use quotient_forge_caqt::{
    Certificate, CostVector, DomainHashes, ExpectedContract, ObserverRecord, OutputRecord,
    RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_check::{
    ActionEmission, ActionId, ActionObligation, EnvironmentInput, FieldId, InputId, ObligationId,
    ObligationRef, Observer, ObserverId, PrivateHistoryId, Release, SemanticContract, SemanticId,
};
use quotient_forge_synth::{
    MachineCell, PlantPair, PlantState, PlantTransition, ReleaseMachine, SynthesisProblem,
};

pub fn canonical_certificate() -> (Vec<u8>, ExpectedContract) {
    let mut certificate = Certificate {
        version: FORMAT_VERSION,
        hashes: DomainHashes::zero(),
        state_count: 2,
        input_count: 1,
        observer_count: 1,
        state_bound: 2,
        claimed_cost: CostVector::default(),
        observers: vec![ObserverRecord {
            id: 0,
            sees_presence: true,
            sees_payload: true,
            sees_actions: true,
        }],
        outputs: vec![
            OutputRecord {
                id: 0,
                emitted: true,
                payload: b"ok".to_vec(),
                actions: Vec::new(),
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"ok".to_vec(),
                actions: Vec::new(),
            },
        ],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
        ],
        relation: vec![RelationPair { left: 0, right: 1 }],
    };
    certificate.seal();
    let expected = ExpectedContract {
        version: FORMAT_VERSION,
        hashes: certificate.hashes,
        state_bound: certificate.state_bound,
        max_cost: certificate.claimed_cost,
    };
    (certificate.encode(), expected)
}

pub fn synthesis_problem() -> SynthesisProblem {
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

pub fn repair_fixture() -> (SynthesisProblem, ReleaseMachine) {
    let semantic = SemanticId::from("same-action");
    let problem = SynthesisProblem {
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
            visible_fields: BTreeSet::from([FieldId::from("leak")]),
            observes_actions: false,
        }],
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![
            Release {
                emitted: true,
                fields: [(FieldId::from("leak"), "0".to_owned())]
                    .into_iter()
                    .collect(),
                actions: Vec::new(),
            },
            Release {
                emitted: true,
                fields: [(FieldId::from("leak"), "1".to_owned())]
                    .into_iter()
                    .collect(),
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
