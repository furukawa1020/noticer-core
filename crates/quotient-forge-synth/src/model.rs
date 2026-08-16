use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use quotient_forge_check::{
    CheckerModel, EnvironmentInput, FaultInput, InitialPair, ModelError, Observer,
    PrivateHistoryId, Release, SemanticContract, SemanticId, State, StateId, Transition,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlantState {
    pub id: u32,
    pub action_semantics: SemanticId,
    pub private_history: PrivateHistoryId,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlantTransition {
    pub from: u32,
    pub input: u32,
    pub to: u32,
    pub machine_symbol: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlantPair {
    pub left: u32,
    pub right: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynthesisProblem {
    pub horizon: u32,
    pub machine_symbol_count: u32,
    pub plant_states: Vec<PlantState>,
    pub plant_transitions: Vec<PlantTransition>,
    pub inputs: Vec<EnvironmentInput>,
    pub semantics: Vec<SemanticContract>,
    pub faults: Vec<FaultInput>,
    pub observers: Vec<Observer>,
    pub initial_pairs: Vec<PlantPair>,
    pub outputs: Vec<Release>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MachineCell {
    pub next_state: u32,
    pub output: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseMachine {
    pub state_count: u32,
    pub symbol_count: u32,
    pub cells: Vec<MachineCell>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SynthesisCost {
    pub states: u64,
    pub emitting_cells: u64,
    pub payload_bytes: u64,
    pub action_emissions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProblemError {
    Empty(&'static str),
    NonCanonical(&'static str),
    OutOfRange(&'static str),
    TableSize,
    UnreachableMachineState(u32),
    Checker(ModelError),
}

impl fmt::Display for ProblemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(domain) => write!(formatter, "{domain} must not be empty"),
            Self::NonCanonical(domain) => write!(formatter, "{domain} is not canonical"),
            Self::OutOfRange(domain) => write!(formatter, "{domain} is out of range"),
            Self::TableSize => formatter.write_str("transition table has the wrong size"),
            Self::UnreachableMachineState(state) => {
                write!(formatter, "machine state {state} is unreachable")
            }
            Self::Checker(error) => write!(formatter, "checker model is invalid: {error}"),
        }
    }
}

impl std::error::Error for ProblemError {}

impl From<ModelError> for ProblemError {
    fn from(error: ModelError) -> Self {
        Self::Checker(error)
    }
}

impl SynthesisProblem {
    pub fn validate(&self) -> Result<(), ProblemError> {
        if self.horizon == 0 {
            return Err(ProblemError::Empty("horizon"));
        }
        if self.machine_symbol_count == 0 {
            return Err(ProblemError::Empty("machine_symbols"));
        }
        if self.plant_states.is_empty() {
            return Err(ProblemError::Empty("plant_states"));
        }
        if self.inputs.is_empty() {
            return Err(ProblemError::Empty("inputs"));
        }
        if self.initial_pairs.is_empty() {
            return Err(ProblemError::Empty("initial_pairs"));
        }
        if self.outputs.is_empty() {
            return Err(ProblemError::Empty("outputs"));
        }
        for (index, state) in self.plant_states.iter().enumerate() {
            if usize_index(state.id) != index {
                return Err(ProblemError::NonCanonical("plant_state_ids"));
            }
        }
        let expected_transitions = self
            .plant_states
            .len()
            .checked_mul(self.inputs.len())
            .ok_or(ProblemError::TableSize)?;
        if self.plant_transitions.len() != expected_transitions {
            return Err(ProblemError::TableSize);
        }
        for (index, transition) in self.plant_transitions.iter().enumerate() {
            let expected_from = index / self.inputs.len();
            let expected_input = index % self.inputs.len();
            if usize_index(transition.from) != expected_from
                || usize_index(transition.input) != expected_input
            {
                return Err(ProblemError::NonCanonical("plant_transitions"));
            }
            if usize_index(transition.to) >= self.plant_states.len() {
                return Err(ProblemError::OutOfRange("plant_transition.to"));
            }
            if transition.machine_symbol >= self.machine_symbol_count {
                return Err(ProblemError::OutOfRange("plant_transition.machine_symbol"));
            }
        }
        for pair in &self.initial_pairs {
            if usize_index(pair.left) >= self.plant_states.len()
                || usize_index(pair.right) >= self.plant_states.len()
                || pair.left == pair.right
            {
                return Err(ProblemError::OutOfRange("initial_pairs"));
            }
        }

        for output_index in 0..self.outputs.len() {
            let probe = ReleaseMachine {
                state_count: 1,
                symbol_count: self.machine_symbol_count,
                cells: vec![
                    MachineCell {
                        next_state: 0,
                        output: u32::try_from(output_index).unwrap_or(u32::MAX),
                    };
                    usize_index(self.machine_symbol_count)
                ],
            };
            self.lower_unchecked(&probe)?.validate()?;
        }
        Ok(())
    }

    pub fn lower_candidate(&self, machine: &ReleaseMachine) -> Result<CheckerModel, ProblemError> {
        self.validate()?;
        machine.validate(self.machine_symbol_count, self.outputs.len())?;
        self.lower_unchecked(machine)
    }

    pub(crate) fn lower_unchecked(
        &self,
        machine: &ReleaseMachine,
    ) -> Result<CheckerModel, ProblemError> {
        let mut states = Vec::with_capacity(
            self.plant_states
                .len()
                .saturating_mul(usize_index(machine.state_count)),
        );
        for plant in &self.plant_states {
            for machine_state in 0..machine.state_count {
                states.push(State {
                    id: combined_state_id(plant.id, machine_state),
                    action_semantics: plant.action_semantics.clone(),
                    private_history: plant.private_history.clone(),
                });
            }
        }

        let mut transitions = Vec::with_capacity(states.len().saturating_mul(self.inputs.len()));
        for plant in &self.plant_states {
            for machine_state in 0..machine.state_count {
                for input_index in 0..self.inputs.len() {
                    let plant_transition = self.plant_transition(plant.id, input_index);
                    let cell = machine.cell(machine_state, plant_transition.machine_symbol);
                    let release = self
                        .outputs
                        .get(usize_index(cell.output))
                        .ok_or(ProblemError::OutOfRange("machine.output"))?
                        .clone();
                    transitions.push(Transition {
                        from: combined_state_id(plant.id, machine_state),
                        input: self.inputs[input_index].id.clone(),
                        to: combined_state_id(plant_transition.to, cell.next_state),
                        release,
                    });
                }
            }
        }

        Ok(CheckerModel {
            horizon: self.horizon,
            states,
            semantics: self.semantics.clone(),
            faults: self.faults.clone(),
            inputs: self.inputs.clone(),
            transitions,
            observers: self.observers.clone(),
            initial_pairs: self
                .initial_pairs
                .iter()
                .map(|pair| InitialPair {
                    left: combined_state_id(pair.left, 0),
                    right: combined_state_id(pair.right, 0),
                })
                .collect(),
        })
    }

    pub(crate) fn plant_transition(&self, state: u32, input: usize) -> PlantTransition {
        self.plant_transitions[usize_index(state) * self.inputs.len() + input]
    }
}

impl ReleaseMachine {
    pub fn validate(&self, symbol_count: u32, output_count: usize) -> Result<(), ProblemError> {
        if self.state_count == 0 || self.symbol_count == 0 {
            return Err(ProblemError::Empty("machine_dimension"));
        }
        if self.symbol_count != symbol_count {
            return Err(ProblemError::OutOfRange("machine.symbol_count"));
        }
        let expected = usize_index(self.state_count)
            .checked_mul(usize_index(self.symbol_count))
            .ok_or(ProblemError::TableSize)?;
        if self.cells.len() != expected {
            return Err(ProblemError::TableSize);
        }
        let mut highest_seen = 0_u32;
        for cell in &self.cells {
            if cell.next_state >= self.state_count || usize_index(cell.output) >= output_count {
                return Err(ProblemError::OutOfRange("machine.cell"));
            }
            if cell.next_state > highest_seen.saturating_add(1) {
                return Err(ProblemError::NonCanonical("first_use_order"));
            }
            highest_seen = highest_seen.max(cell.next_state);
        }
        if highest_seen.saturating_add(1) != self.state_count {
            return Err(ProblemError::NonCanonical("first_use_order"));
        }
        if let Some(state) = self.first_unreachable_state() {
            return Err(ProblemError::UnreachableMachineState(state));
        }
        Ok(())
    }

    #[must_use]
    pub fn cell(&self, state: u32, symbol: u32) -> MachineCell {
        self.cells[usize_index(state) * usize_index(self.symbol_count) + usize_index(symbol)]
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.cells.len() * 8);
        bytes.extend_from_slice(&self.state_count.to_le_bytes());
        bytes.extend_from_slice(&self.symbol_count.to_le_bytes());
        for cell in &self.cells {
            bytes.extend_from_slice(&cell.next_state.to_le_bytes());
            bytes.extend_from_slice(&cell.output.to_le_bytes());
        }
        bytes
    }

    #[must_use]
    pub fn cost(&self, outputs: &[Release]) -> SynthesisCost {
        let mut cost = SynthesisCost {
            states: u64::from(self.state_count),
            emitting_cells: 0,
            payload_bytes: 0,
            action_emissions: 0,
        };
        for cell in &self.cells {
            if let Some(output) = outputs.get(usize_index(cell.output)) {
                cost.emitting_cells = cost
                    .emitting_cells
                    .saturating_add(u64::from(output.emitted));
                cost.payload_bytes = cost.payload_bytes.saturating_add(
                    output
                        .fields
                        .values()
                        .map(|value| u64::try_from(value.len()).unwrap_or(u64::MAX))
                        .sum(),
                );
                cost.action_emissions = cost
                    .action_emissions
                    .saturating_add(u64::try_from(output.actions.len()).unwrap_or(u64::MAX));
            }
        }
        cost
    }

    fn first_unreachable_state(&self) -> Option<u32> {
        let mut reachable = vec![false; usize_index(self.state_count)];
        reachable[0] = true;
        let mut queue = VecDeque::from([0_u32]);
        while let Some(state) = queue.pop_front() {
            for symbol in 0..self.symbol_count {
                let next = self.cell(state, symbol).next_state;
                if !reachable[usize_index(next)] {
                    reachable[usize_index(next)] = true;
                    queue.push_back(next);
                }
            }
        }
        reachable
            .iter()
            .position(|is_reachable| !is_reachable)
            .map(|state| u32::try_from(state).unwrap_or(u32::MAX))
    }
}

pub(crate) fn parse_combined_state(id: &StateId) -> Option<(u32, u32)> {
    let value = id.as_str().strip_prefix('p')?;
    let (plant, machine) = value.split_once(":m")?;
    Some((plant.parse().ok()?, machine.parse().ok()?))
}

fn combined_state_id(plant: u32, machine: u32) -> StateId {
    StateId::new(format!("p{plant}:m{machine}"))
}

fn usize_index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[allow(dead_code)]
fn _assert_private_histories_are_not_machine_states(values: &[PrivateHistoryId]) -> BTreeSet<&str> {
    values.iter().map(PrivateHistoryId::as_str).collect()
}
