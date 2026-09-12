//! Deterministic materialization for the K7 reference scalability backend.

use std::collections::{BTreeMap, BTreeSet};

use quotient_forge_check::{
    ActionEmission, ActionId, ActionObligation, EnvironmentInput, FaultInput, FaultInputId,
    FieldId, InputId, ObligationId, ObligationRef, Observer, ObserverId, PrivateHistoryId, Release,
    SemanticContract, SemanticId,
};

use crate::{
    MachineCell, PlantPair, PlantState, PlantTransition, ReleaseMachine, SynthesisProblem,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalabilityDimensions {
    pub plant_states: u32,
    pub machine_states: u32,
    pub horizon: u32,
    pub observers: u32,
    pub fault_states: u32,
    pub output_alphabet: u32,
    pub quotient_classes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedReferenceCase {
    pub problem: SynthesisProblem,
    pub candidate: ReleaseMachine,
}

pub fn materialize_reference_case(
    dimensions: ScalabilityDimensions,
) -> Result<MaterializedReferenceCase, String> {
    validate_dimensions(dimensions)?;

    let semantics = (0..dimensions.quotient_classes)
        .map(|class| semantic_contract(class, dimensions.horizon))
        .collect::<Vec<_>>();
    let states = (0..dimensions.plant_states)
        .map(|id| PlantState {
            id,
            action_semantics: semantic_id(id % dimensions.quotient_classes),
            private_history: PrivateHistoryId::new(format!("private-history-{id}")),
        })
        .collect::<Vec<_>>();
    let inputs = environment_inputs(dimensions.fault_states);
    let symbol_count = dimensions.quotient_classes;
    let transitions = states
        .iter()
        .flat_map(|state| {
            inputs
                .iter()
                .enumerate()
                .map(move |(input, _)| PlantTransition {
                    from: state.id,
                    input: u32::try_from(input).expect("validated bounded input count"),
                    to: state.id,
                    machine_symbol: state.id % dimensions.quotient_classes,
                })
        })
        .collect();
    let initial_pairs = (0..dimensions.quotient_classes)
        .map(|class| {
            let members = states
                .iter()
                .filter(|state| state.id % dimensions.quotient_classes == class)
                .map(|state| state.id)
                .collect::<Vec<_>>();
            PlantPair {
                left: members[0],
                right: members[1],
            }
        })
        .collect();
    let outputs = outputs(dimensions.output_alphabet, dimensions.quotient_classes);
    let observers = (0..dimensions.observers)
        .map(|id| Observer {
            id: ObserverId::new(format!("observer-{id}")),
            visible_fields: [FieldId::from("release-class")]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            observes_actions: true,
        })
        .collect();
    let faults = (0..dimensions.fault_states)
        .map(|id| FaultInput {
            id: FaultInputId::new(format!("fault-{id}")),
            recovery: None,
        })
        .collect();

    let problem = SynthesisProblem {
        horizon: dimensions.horizon,
        machine_symbol_count: symbol_count,
        plant_states: states,
        plant_transitions: transitions,
        inputs,
        semantics,
        faults,
        observers,
        initial_pairs,
        outputs,
    };
    problem.validate().map_err(|error| error.to_string())?;

    let mut cells = Vec::new();
    for state in 0..dimensions.machine_states {
        for class in 0..dimensions.quotient_classes {
            cells.push(MachineCell {
                next_state: (state + 1).min(dimensions.machine_states - 1),
                output: if state + 1 >= dimensions.horizon {
                    class
                } else {
                    dimensions.quotient_classes
                },
            });
        }
    }
    let candidate = ReleaseMachine {
        state_count: dimensions.machine_states,
        symbol_count,
        cells,
    };
    problem
        .lower_candidate(&candidate)
        .map_err(|error| error.to_string())?;

    Ok(MaterializedReferenceCase { problem, candidate })
}

fn validate_dimensions(dimensions: ScalabilityDimensions) -> Result<(), String> {
    if dimensions.horizon == 0
        || dimensions.machine_states == 0
        || dimensions.observers == 0
        || dimensions.quotient_classes == 0
    {
        return Err(
            "horizon, machine_states, observers, and quotient_classes must be positive".to_owned(),
        );
    }
    if dimensions.plant_states < dimensions.quotient_classes.saturating_mul(2) {
        return Err(
            "plant_states must provide two private histories per quotient class".to_owned(),
        );
    }
    if dimensions.output_alphabet <= dimensions.quotient_classes {
        return Err(
            "output_alphabet must include one action output per class and padding".to_owned(),
        );
    }
    Ok(())
}

fn semantic_id(class: u32) -> SemanticId {
    SemanticId::new(format!("semantic-{class}"))
}

fn obligation_id(class: u32) -> ObligationId {
    ObligationId::new(format!("obligation-{class}"))
}

fn semantic_contract(class: u32, horizon: u32) -> SemanticContract {
    SemanticContract {
        id: semantic_id(class),
        obligations: vec![ActionObligation {
            id: obligation_id(class),
            action: ActionId::new(format!("action-{class}")),
            trigger_slot: horizon - 1,
            deadline_slot: horizon - 1,
        }],
    }
}

fn environment_inputs(fault_states: u32) -> Vec<EnvironmentInput> {
    let mut inputs = vec![EnvironmentInput {
        id: InputId::from("nominal"),
        public_symbol: "tick".to_owned(),
        fault: None,
    }];
    inputs.extend((0..fault_states).map(|id| EnvironmentInput {
        id: InputId::new(format!("fault-input-{id}")),
        public_symbol: format!("fault-{id}"),
        fault: Some(FaultInputId::new(format!("fault-{id}"))),
    }));
    inputs
}

fn outputs(output_alphabet: u32, quotient_classes: u32) -> Vec<Release> {
    let mut releases = (0..quotient_classes)
        .map(|class| Release {
            emitted: true,
            fields: BTreeMap::from([(FieldId::from("release-class"), class.to_string())]),
            actions: vec![ActionEmission {
                obligation: ObligationRef::Authorized(obligation_id(class)),
                action: ActionId::new(format!("action-{class}")),
            }],
        })
        .collect::<Vec<_>>();
    releases.extend((quotient_classes..output_alphabet).map(|symbol| Release {
        emitted: true,
        fields: BTreeMap::from([(FieldId::from("release-class"), format!("padding-{symbol}"))]),
        actions: Vec::new(),
    }));
    releases
}
