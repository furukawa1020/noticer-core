use crate::canonical::{canonical_hash, CanonicalEncode, Encoder};
use crate::{FaultStateId, IrError, IrLimits, UtilityStateId, DOMAIN_FAULT, DOMAIN_UTILITY};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtilityState {
    pub id: UtilityStateId,
    pub accepting: bool,
    pub rejecting: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtilityTransition {
    pub from: UtilityStateId,
    pub symbol: u16,
    pub to: UtilityStateId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtilityAutomaton {
    pub states: Vec<UtilityState>,
    pub initial: UtilityStateId,
    pub alphabet_size: u16,
    pub transitions: Vec<UtilityTransition>,
}

impl UtilityAutomaton {
    pub fn validate(&self, limits: IrLimits) -> Result<(), IrError> {
        validate_utility(self, limits)
    }

    pub fn canonicalized(&self, limits: IrLimits) -> Result<Self, IrError> {
        self.validate(limits)?;
        let states: BTreeMap<_, _> = self.states.iter().map(|state| (state.id, *state)).collect();
        let mut outgoing: BTreeMap<UtilityStateId, Vec<UtilityTransition>> = BTreeMap::new();
        for transition in &self.transitions {
            outgoing
                .entry(transition.from)
                .or_default()
                .push(*transition);
        }
        for transitions in outgoing.values_mut() {
            transitions.sort_by_key(|transition| (transition.symbol, transition.to));
        }
        let mut rename = BTreeMap::from([(self.initial, UtilityStateId(0))]);
        let mut queue = VecDeque::from([self.initial]);
        while let Some(current) = queue.pop_front() {
            if let Some(transitions) = outgoing.get(&current) {
                for transition in transitions {
                    if !rename.contains_key(&transition.to) {
                        let next = UtilityStateId(rename.len() as u16);
                        rename.insert(transition.to, next);
                        queue.push_back(transition.to);
                    }
                }
            }
        }
        let mut canonical_states: Vec<_> = rename
            .iter()
            .map(|(old, new)| UtilityState {
                id: *new,
                accepting: states[old].accepting,
                rejecting: states[old].rejecting,
            })
            .collect();
        canonical_states.sort_by_key(|state| state.id);
        let mut transitions = self
            .transitions
            .iter()
            .filter_map(|transition| {
                Some(UtilityTransition {
                    from: *rename.get(&transition.from)?,
                    symbol: transition.symbol,
                    to: *rename.get(&transition.to)?,
                })
            })
            .collect::<Vec<_>>();
        transitions.sort_by_key(|transition| (transition.from, transition.symbol, transition.to));
        let canonical = Self {
            states: canonical_states,
            initial: UtilityStateId(0),
            alphabet_size: self.alphabet_size,
            transitions,
        };
        canonical.validate(limits)?;
        Ok(canonical)
    }

    pub fn is_canonical(&self, limits: IrLimits) -> Result<bool, IrError> {
        Ok(self == &self.canonicalized(limits)?)
    }

    pub fn canonical_hash(&self, limits: IrLimits) -> Result<[u8; 32], IrError> {
        let canonical = self.canonicalized(limits)?;
        Ok(canonical_hash(DOMAIN_UTILITY, &canonical))
    }
}

impl CanonicalEncode for UtilityAutomaton {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.initial.0);
        encoder.u16(self.alphabet_size);
        encoder.usize(self.states.len());
        for state in &self.states {
            encoder.u16(state.id.0);
            encoder.bool(state.accepting);
            encoder.bool(state.rejecting);
        }
        encoder.usize(self.transitions.len());
        for transition in &self.transitions {
            encoder.u16(transition.from.0);
            encoder.u16(transition.symbol);
            encoder.u16(transition.to.0);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultState {
    pub id: FaultStateId,
    pub recoverable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultTransition {
    pub from: FaultStateId,
    pub symbol: u16,
    pub to: FaultStateId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultAutomaton {
    pub states: Vec<FaultState>,
    pub initial: FaultStateId,
    pub alphabet_size: u16,
    pub transitions: Vec<FaultTransition>,
}

impl FaultAutomaton {
    pub fn validate(&self, limits: IrLimits) -> Result<(), IrError> {
        validate_fault(self, limits)
    }

    pub fn canonicalized(&self, limits: IrLimits) -> Result<Self, IrError> {
        self.validate(limits)?;
        let states: BTreeMap<_, _> = self.states.iter().map(|state| (state.id, *state)).collect();
        let mut outgoing: BTreeMap<FaultStateId, Vec<FaultTransition>> = BTreeMap::new();
        for transition in &self.transitions {
            outgoing
                .entry(transition.from)
                .or_default()
                .push(*transition);
        }
        for transitions in outgoing.values_mut() {
            transitions.sort_by_key(|transition| (transition.symbol, transition.to));
        }
        let mut rename = BTreeMap::from([(self.initial, FaultStateId(0))]);
        let mut queue = VecDeque::from([self.initial]);
        while let Some(current) = queue.pop_front() {
            if let Some(transitions) = outgoing.get(&current) {
                for transition in transitions {
                    if !rename.contains_key(&transition.to) {
                        let next = FaultStateId(rename.len() as u16);
                        rename.insert(transition.to, next);
                        queue.push_back(transition.to);
                    }
                }
            }
        }
        let mut canonical_states: Vec<_> = rename
            .iter()
            .map(|(old, new)| FaultState {
                id: *new,
                recoverable: states[old].recoverable,
            })
            .collect();
        canonical_states.sort_by_key(|state| state.id);
        let mut transitions = self
            .transitions
            .iter()
            .filter_map(|transition| {
                Some(FaultTransition {
                    from: *rename.get(&transition.from)?,
                    symbol: transition.symbol,
                    to: *rename.get(&transition.to)?,
                })
            })
            .collect::<Vec<_>>();
        transitions.sort_by_key(|transition| (transition.from, transition.symbol, transition.to));
        let canonical = Self {
            states: canonical_states,
            initial: FaultStateId(0),
            alphabet_size: self.alphabet_size,
            transitions,
        };
        canonical.validate(limits)?;
        Ok(canonical)
    }

    pub fn is_canonical(&self, limits: IrLimits) -> Result<bool, IrError> {
        Ok(self == &self.canonicalized(limits)?)
    }

    pub fn canonical_hash(&self, limits: IrLimits) -> Result<[u8; 32], IrError> {
        let canonical = self.canonicalized(limits)?;
        Ok(canonical_hash(DOMAIN_FAULT, &canonical))
    }
}

impl CanonicalEncode for FaultAutomaton {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.initial.0);
        encoder.u16(self.alphabet_size);
        encoder.usize(self.states.len());
        for state in &self.states {
            encoder.u16(state.id.0);
            encoder.bool(state.recoverable);
        }
        encoder.usize(self.transitions.len());
        for transition in &self.transitions {
            encoder.u16(transition.from.0);
            encoder.u16(transition.symbol);
            encoder.u16(transition.to.0);
        }
    }
}

fn validate_utility(machine: &UtilityAutomaton, limits: IrLimits) -> Result<(), IrError> {
    const COMPONENT: &str = "utility automaton";
    if machine
        .states
        .iter()
        .any(|state| state.accepting && state.rejecting)
    {
        return Err(IrError::InvalidUtility);
    }
    validate_dfa(
        COMPONENT,
        machine.states.iter().map(|state| state.id.0),
        machine.initial.0,
        machine.alphabet_size,
        machine
            .transitions
            .iter()
            .map(|transition| (transition.from.0, transition.symbol, transition.to.0)),
        limits,
    )
}

fn validate_fault(machine: &FaultAutomaton, limits: IrLimits) -> Result<(), IrError> {
    validate_dfa(
        "fault automaton",
        machine.states.iter().map(|state| state.id.0),
        machine.initial.0,
        machine.alphabet_size,
        machine
            .transitions
            .iter()
            .map(|transition| (transition.from.0, transition.symbol, transition.to.0)),
        limits,
    )
}

fn validate_dfa(
    component: &'static str,
    states: impl Iterator<Item = u16>,
    initial: u16,
    alphabet_size: u16,
    transitions: impl Iterator<Item = (u16, u16, u16)>,
    limits: IrLimits,
) -> Result<(), IrError> {
    let state_values: Vec<_> = states.collect();
    if state_values.is_empty() {
        return Err(IrError::EmptyStates { component });
    }
    if state_values.len() > limits.max_states || alphabet_size == 0 {
        return Err(IrError::LimitExceeded { component });
    }
    let ids: BTreeSet<_> = state_values.iter().copied().collect();
    if ids.len() != state_values.len() {
        return Err(IrError::Duplicate { component });
    }
    if !ids.contains(&initial) {
        return Err(IrError::InvalidInitial { component });
    }
    let transitions: Vec<_> = transitions.collect();
    if transitions.len() > limits.max_transitions {
        return Err(IrError::LimitExceeded { component });
    }
    let mut keys = BTreeSet::new();
    for (from, symbol, to) in &transitions {
        if !ids.contains(from) || !ids.contains(to) || *symbol >= alphabet_size {
            return Err(IrError::InvalidReference { component });
        }
        if !keys.insert((*from, *symbol)) {
            return Err(IrError::Duplicate { component });
        }
    }
    let expected = state_values
        .len()
        .checked_mul(usize::from(alphabet_size))
        .ok_or(IrError::LimitExceeded { component })?;
    if expected != transitions.len() {
        return Err(IrError::NonTotal { component });
    }
    Ok(())
}
