//! Canonical finite-state machine representatives under state renaming.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const STATE_SYMMETRY_SCHEMA_V1: &str = "noticer.quotient_forge.state_symmetry.v1";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SymmetryCell {
    pub state: u32,
    pub symbol: u32,
    pub next_state: u32,
    pub output_sha256: String,
}

impl SymmetryCell {
    pub fn new(
        state: u32,
        symbol: u32,
        next_state: u32,
        output_sha256: impl Into<String>,
    ) -> Result<Self, SymmetryError> {
        let cell = Self {
            state,
            symbol,
            next_state,
            output_sha256: output_sha256.into(),
        };
        require_sha256("output_sha256", &cell.output_sha256)?;
        Ok(cell)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SymmetryMachine {
    pub state_count: u32,
    pub symbol_count: u32,
    pub initial_state: u32,
    pub cells: Vec<SymmetryCell>,
}

impl SymmetryMachine {
    pub fn new(
        state_count: u32,
        symbol_count: u32,
        initial_state: u32,
        mut cells: Vec<SymmetryCell>,
    ) -> Result<Self, SymmetryError> {
        cells.sort_by_key(|cell| (cell.state, cell.symbol));
        let machine = Self {
            state_count,
            symbol_count,
            initial_state,
            cells,
        };
        machine.validate()?;
        Ok(machine)
    }

    pub fn validate(&self) -> Result<(), SymmetryError> {
        if self.state_count == 0 || self.symbol_count == 0 {
            return Err(SymmetryError::EmptyMachine);
        }
        if self.initial_state >= self.state_count {
            return Err(SymmetryError::InvalidInitialState);
        }
        let expected_len = u64::from(self.state_count)
            .checked_mul(u64::from(self.symbol_count))
            .ok_or(SymmetryError::MachineTooLarge)?;
        if u64::try_from(self.cells.len()).map_err(|_| SymmetryError::MachineTooLarge)?
            != expected_len
        {
            return Err(SymmetryError::NonTotalMachine);
        }
        for (index, cell) in self.cells.iter().enumerate() {
            let index = u64::try_from(index).map_err(|_| SymmetryError::MachineTooLarge)?;
            let expected_state = u32::try_from(index / u64::from(self.symbol_count))
                .map_err(|_| SymmetryError::MachineTooLarge)?;
            let expected_symbol = u32::try_from(index % u64::from(self.symbol_count))
                .map_err(|_| SymmetryError::MachineTooLarge)?;
            if cell.state != expected_state || cell.symbol != expected_symbol {
                return Err(SymmetryError::NonTotalMachine);
            }
            if cell.next_state >= self.state_count {
                return Err(SymmetryError::InvalidNextState);
            }
            require_sha256("output_sha256", &cell.output_sha256)?;
        }
        Ok(())
    }

    pub fn machine_sha256(&self) -> Result<String, SymmetryError> {
        self.validate()?;
        canonical_json_sha256(self)
    }

    fn cell(&self, state: u32, symbol: u32) -> &SymmetryCell {
        let index = u64::from(state) * u64::from(self.symbol_count) + u64::from(symbol);
        &self.cells[usize::try_from(index).expect("validated machine index must fit usize")]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineCheckDecision {
    Valid,
    Invalid,
    Inconclusive,
}

pub trait SymmetryMachineChecker {
    fn check(&mut self, machine: &SymmetryMachine) -> MachineCheckDecision;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SymmetryLimits {
    pub max_unreachable_states: u32,
    pub max_unreachable_permutations: u64,
}

impl SymmetryLimits {
    fn validate(&self) -> Result<(), SymmetryError> {
        if self.max_unreachable_permutations == 0 {
            return Err(SymmetryError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StateRename {
    pub original_state: u32,
    pub canonical_state: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateSymmetryArtifact {
    pub schema_version: String,
    pub original_machine_sha256: String,
    pub canonical_machine_sha256: String,
    pub state_count: u32,
    pub symbol_count: u32,
    pub reachable_state_count: u32,
    pub unreachable_state_count: u32,
    pub unreachable_permutations_evaluated: u64,
    pub checker_calls: u64,
    pub original_decision: MachineCheckDecision,
    pub canonical_decision: MachineCheckDecision,
    pub witness_verified: bool,
    pub decision_preserved: bool,
    pub canonicalization_enabled: bool,
    pub witness_persisted: bool,
    pub artifact_sha256: String,
}

impl StateSymmetryArtifact {
    pub fn validate(&self) -> Result<(), SymmetryError> {
        if self.schema_version != STATE_SYMMETRY_SCHEMA_V1 {
            return Err(SymmetryError::SchemaVersion);
        }
        require_sha256("original_machine_sha256", &self.original_machine_sha256)?;
        require_sha256("canonical_machine_sha256", &self.canonical_machine_sha256)?;
        require_sha256("artifact_sha256", &self.artifact_sha256)?;
        let expected_preserved = self.witness_verified
            && self.original_decision != MachineCheckDecision::Inconclusive
            && self.original_decision == self.canonical_decision;
        if self.state_count == 0
            || self.symbol_count == 0
            || self.reachable_state_count + self.unreachable_state_count != self.state_count
            || self.unreachable_permutations_evaluated == 0
            || self.checker_calls != 2
            || self.decision_preserved != expected_preserved
            || self.canonicalization_enabled != expected_preserved
            || self.witness_persisted
        {
            return Err(SymmetryError::InvalidArtifact);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(SymmetryError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSymmetryResult {
    pub canonical_machine: SymmetryMachine,
    pub artifact: StateSymmetryArtifact,
    witness: Vec<StateRename>,
}

impl StateSymmetryResult {
    pub fn witness(&self) -> &[StateRename] {
        &self.witness
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SymmetryError {
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("machine must have at least one state and symbol")]
    EmptyMachine,
    #[error("initial state is outside the machine")]
    InvalidInitialState,
    #[error("next state is outside the machine")]
    InvalidNextState,
    #[error("machine transition table is not total and canonical")]
    NonTotalMachine,
    #[error("machine exceeds representable bounds")]
    MachineTooLarge,
    #[error("symmetry limits are invalid")]
    InvalidLimits,
    #[error("unreachable-state permutation bound was exceeded")]
    PermutationLimitExceeded,
    #[error("canonical permutation search produced no candidate")]
    NoCanonicalCandidate,
    #[error("generated state-renaming witness failed validation")]
    InvalidWitness,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("state-symmetry artifact is inconsistent")]
    InvalidArtifact,
    #[error("{0} does not match its canonical payload")]
    DigestMismatch(&'static str),
    #[error("canonical serialization failed")]
    Serialization,
}

pub fn canonicalize_state_symmetry<Checker: SymmetryMachineChecker>(
    machine: &SymmetryMachine,
    limits: &SymmetryLimits,
    checker: &mut Checker,
) -> Result<StateSymmetryResult, SymmetryError> {
    machine.validate()?;
    limits.validate()?;
    let reachable = reachable_order(machine);
    let reachable_set = reachable.iter().copied().collect::<BTreeSet<_>>();
    let mut unreachable = (0..machine.state_count)
        .filter(|state| !reachable_set.contains(state))
        .collect::<Vec<_>>();
    if u32::try_from(unreachable.len()).map_err(|_| SymmetryError::MachineTooLarge)?
        > limits.max_unreachable_states
    {
        return Err(SymmetryError::PermutationLimitExceeded);
    }
    let permutation_count = factorial(unreachable.len())?;
    if permutation_count > limits.max_unreachable_permutations {
        return Err(SymmetryError::PermutationLimitExceeded);
    }

    let mut best: Option<(Vec<u8>, SymmetryMachine, Vec<u32>)> = None;
    visit_permutations(&mut unreachable, 0, &mut |permutation| {
        let mut order = reachable.clone();
        order.extend_from_slice(permutation);
        let candidate = relabel_machine(machine, &order)?;
        let encoding = serde_json::to_vec(&candidate).map_err(|_| SymmetryError::Serialization)?;
        if best
            .as_ref()
            .is_none_or(|(current, _, _)| encoding < *current)
        {
            best = Some((encoding, candidate, order));
        }
        Ok(())
    })?;
    let (_, canonical_machine, canonical_order) =
        best.ok_or(SymmetryError::NoCanonicalCandidate)?;
    let original_to_canonical = canonical_order
        .iter()
        .enumerate()
        .map(|(canonical, original)| {
            Ok(StateRename {
                original_state: *original,
                canonical_state: u32::try_from(canonical)
                    .map_err(|_| SymmetryError::MachineTooLarge)?,
            })
        })
        .collect::<Result<Vec<_>, SymmetryError>>()?;
    let mut witness = original_to_canonical;
    witness.sort_by_key(|rename| rename.original_state);
    if !verify_state_renaming(machine, &canonical_machine, &witness)? {
        return Err(SymmetryError::InvalidWitness);
    }

    let original_decision = checker.check(machine);
    let canonical_decision = checker.check(&canonical_machine);
    let decision_preserved = original_decision != MachineCheckDecision::Inconclusive
        && original_decision == canonical_decision;
    let mut artifact = StateSymmetryArtifact {
        schema_version: STATE_SYMMETRY_SCHEMA_V1.to_owned(),
        original_machine_sha256: machine.machine_sha256()?,
        canonical_machine_sha256: canonical_machine.machine_sha256()?,
        state_count: machine.state_count,
        symbol_count: machine.symbol_count,
        reachable_state_count: u32::try_from(reachable.len())
            .map_err(|_| SymmetryError::MachineTooLarge)?,
        unreachable_state_count: u32::try_from(unreachable.len())
            .map_err(|_| SymmetryError::MachineTooLarge)?,
        unreachable_permutations_evaluated: permutation_count,
        checker_calls: 2,
        original_decision,
        canonical_decision,
        witness_verified: true,
        decision_preserved,
        canonicalization_enabled: decision_preserved,
        witness_persisted: false,
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate()?;
    Ok(StateSymmetryResult {
        canonical_machine,
        artifact,
        witness,
    })
}

pub fn verify_state_renaming(
    original: &SymmetryMachine,
    canonical: &SymmetryMachine,
    witness: &[StateRename],
) -> Result<bool, SymmetryError> {
    original.validate()?;
    canonical.validate()?;
    if original.state_count != canonical.state_count
        || original.symbol_count != canonical.symbol_count
        || witness.len() != usize::try_from(original.state_count).unwrap_or(usize::MAX)
    {
        return Ok(false);
    }
    let mapping = witness
        .iter()
        .map(|rename| (rename.original_state, rename.canonical_state))
        .collect::<BTreeMap<_, _>>();
    let canonical_states = witness
        .iter()
        .map(|rename| rename.canonical_state)
        .collect::<BTreeSet<_>>();
    if mapping.len() != witness.len()
        || canonical_states.len() != witness.len()
        || mapping.get(&original.initial_state) != Some(&canonical.initial_state)
        || mapping.keys().copied().ne(0..original.state_count)
        || canonical_states
            .iter()
            .copied()
            .ne(0..canonical.state_count)
    {
        return Ok(false);
    }
    for cell in &original.cells {
        let Some(&state) = mapping.get(&cell.state) else {
            return Ok(false);
        };
        let Some(&next_state) = mapping.get(&cell.next_state) else {
            return Ok(false);
        };
        let canonical_cell = canonical.cell(state, cell.symbol);
        if canonical_cell.next_state != next_state
            || canonical_cell.output_sha256 != cell.output_sha256
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn reachable_order(machine: &SymmetryMachine) -> Vec<u32> {
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([machine.initial_state]);
    seen.insert(machine.initial_state);
    while let Some(state) = queue.pop_front() {
        order.push(state);
        for symbol in 0..machine.symbol_count {
            let next = machine.cell(state, symbol).next_state;
            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    order
}

fn relabel_machine(
    machine: &SymmetryMachine,
    canonical_order: &[u32],
) -> Result<SymmetryMachine, SymmetryError> {
    let mapping = canonical_order
        .iter()
        .enumerate()
        .map(|(canonical, original)| {
            Ok((
                *original,
                u32::try_from(canonical).map_err(|_| SymmetryError::MachineTooLarge)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, SymmetryError>>()?;
    let mut cells = Vec::with_capacity(machine.cells.len());
    for (canonical_state, original_state) in canonical_order.iter().enumerate() {
        let canonical_state =
            u32::try_from(canonical_state).map_err(|_| SymmetryError::MachineTooLarge)?;
        for symbol in 0..machine.symbol_count {
            let cell = machine.cell(*original_state, symbol);
            cells.push(SymmetryCell {
                state: canonical_state,
                symbol,
                next_state: *mapping
                    .get(&cell.next_state)
                    .ok_or(SymmetryError::InvalidWitness)?,
                output_sha256: cell.output_sha256.clone(),
            });
        }
    }
    SymmetryMachine::new(machine.state_count, machine.symbol_count, 0, cells)
}

fn factorial(count: usize) -> Result<u64, SymmetryError> {
    (2..=count).try_fold(1_u64, |value, factor| {
        value
            .checked_mul(u64::try_from(factor).map_err(|_| SymmetryError::MachineTooLarge)?)
            .ok_or(SymmetryError::MachineTooLarge)
    })
}

fn visit_permutations(
    states: &mut [u32],
    start: usize,
    visitor: &mut impl FnMut(&[u32]) -> Result<(), SymmetryError>,
) -> Result<(), SymmetryError> {
    if start == states.len() {
        return visitor(states);
    }
    for index in start..states.len() {
        states.swap(start, index);
        visit_permutations(states, start + 1, visitor)?;
        states.swap(start, index);
    }
    Ok(())
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), SymmetryError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(SymmetryError::InvalidSha256(field))
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, SymmetryError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SymmetryError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
