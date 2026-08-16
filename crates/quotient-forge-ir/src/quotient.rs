use crate::canonical::{canonical_hash, CanonicalEncode, Encoder};
use crate::{IrError, IrLimits, PlantStateId, QuotientStateId, DOMAIN_QUOTIENT};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionSemanticsLabel {
    pub service: String,
    pub action: String,
    pub public_bucket: u32,
    pub release_window_start: u16,
    pub release_deadline: u16,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuotientLabel {
    NoAction,
    Action(ActionSemanticsLabel),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientState {
    pub id: QuotientStateId,
    pub semantics: QuotientLabel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientTransition {
    pub from: QuotientStateId,
    pub symbol: u16,
    pub to: QuotientStateId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlantQuotientProjection {
    pub plant: PlantStateId,
    pub quotient: QuotientStateId,
    pub semantics: QuotientLabel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientMonitor {
    pub states: Vec<QuotientState>,
    pub initial: QuotientStateId,
    pub alphabet_size: u16,
    pub transitions: Vec<QuotientTransition>,
    pub plant_state_count: u16,
    pub projection: Vec<PlantQuotientProjection>,
}

impl QuotientMonitor {
    pub fn validate(&self, limits: IrLimits) -> Result<(), IrError> {
        const COMPONENT: &str = "quotient monitor";
        if self.states.is_empty() {
            return Err(IrError::EmptyStates {
                component: COMPONENT,
            });
        }
        if self.states.len() > limits.max_states || self.transitions.len() > limits.max_transitions
        {
            return Err(IrError::LimitExceeded {
                component: COMPONENT,
            });
        }
        if self.alphabet_size == 0 || self.plant_state_count == 0 {
            return Err(IrError::InvalidReference {
                component: COMPONENT,
            });
        }
        let states: BTreeMap<_, _> = self.states.iter().map(|state| (state.id, state)).collect();
        if states.len() != self.states.len() {
            return Err(IrError::Duplicate {
                component: COMPONENT,
            });
        }
        if !states.contains_key(&self.initial) {
            return Err(IrError::InvalidInitial {
                component: COMPONENT,
            });
        }
        for state in &self.states {
            validate_semantics(&state.semantics, limits)?;
        }
        let mut keys = BTreeSet::new();
        for transition in &self.transitions {
            if !states.contains_key(&transition.from)
                || !states.contains_key(&transition.to)
                || transition.symbol >= self.alphabet_size
            {
                return Err(IrError::InvalidReference {
                    component: COMPONENT,
                });
            }
            if !keys.insert((transition.from, transition.symbol)) {
                return Err(IrError::Duplicate {
                    component: COMPONENT,
                });
            }
        }
        let expected = self
            .states
            .len()
            .checked_mul(usize::from(self.alphabet_size))
            .ok_or(IrError::LimitExceeded {
                component: COMPONENT,
            })?;
        if self.transitions.len() != expected {
            return Err(IrError::NonTotal {
                component: COMPONENT,
            });
        }
        if self.projection.len() != usize::from(self.plant_state_count) {
            return Err(IrError::QuotientMismatch);
        }
        let mut plant_ids = BTreeSet::new();
        for projection in &self.projection {
            if projection.plant.0 >= self.plant_state_count || !plant_ids.insert(projection.plant) {
                return Err(IrError::QuotientMismatch);
            }
            let Some(state) = states.get(&projection.quotient) else {
                return Err(IrError::QuotientMismatch);
            };
            if state.semantics != projection.semantics {
                return Err(IrError::QuotientMismatch);
            }
        }
        Ok(())
    }

    pub fn canonicalized(&self, limits: IrLimits) -> Result<Self, IrError> {
        self.validate(limits)?;
        let states: BTreeMap<_, _> = self.states.iter().map(|state| (state.id, state)).collect();
        let mut outgoing: BTreeMap<QuotientStateId, Vec<&QuotientTransition>> = BTreeMap::new();
        for transition in &self.transitions {
            outgoing
                .entry(transition.from)
                .or_default()
                .push(transition);
        }
        for transitions in outgoing.values_mut() {
            transitions.sort_by_key(|transition| (transition.symbol, transition.to));
        }
        let mut rename = BTreeMap::from([(self.initial, QuotientStateId(0))]);
        let mut queue = VecDeque::from([self.initial]);
        while let Some(current) = queue.pop_front() {
            if let Some(transitions) = outgoing.get(&current) {
                for transition in transitions {
                    if !rename.contains_key(&transition.to) {
                        let next = QuotientStateId(rename.len() as u16);
                        rename.insert(transition.to, next);
                        queue.push_back(transition.to);
                    }
                }
            }
        }
        let mut canonical_states: Vec<_> = rename
            .iter()
            .map(|(old, new)| QuotientState {
                id: *new,
                semantics: states[old].semantics.clone(),
            })
            .collect();
        canonical_states.sort_by_key(|state| state.id);
        let mut transitions = Vec::new();
        for transition in &self.transitions {
            let (Some(from), Some(to)) = (rename.get(&transition.from), rename.get(&transition.to))
            else {
                continue;
            };
            transitions.push(QuotientTransition {
                from: *from,
                symbol: transition.symbol,
                to: *to,
            });
        }
        transitions.sort_by_key(|transition| (transition.from, transition.symbol, transition.to));
        let mut projection: Vec<_> = self
            .projection
            .iter()
            .filter_map(|item| {
                rename
                    .get(&item.quotient)
                    .map(|quotient| PlantQuotientProjection {
                        plant: item.plant,
                        quotient: *quotient,
                        semantics: item.semantics.clone(),
                    })
            })
            .collect();
        projection.sort_by_key(|item| item.plant);
        let canonical = Self {
            states: canonical_states,
            initial: QuotientStateId(0),
            alphabet_size: self.alphabet_size,
            transitions,
            plant_state_count: self.plant_state_count,
            projection,
        };
        canonical.validate(limits)?;
        Ok(canonical)
    }

    pub fn is_canonical(&self, limits: IrLimits) -> Result<bool, IrError> {
        Ok(self == &self.canonicalized(limits)?)
    }

    pub fn canonical_hash(&self, limits: IrLimits) -> Result<[u8; 32], IrError> {
        let canonical = self.canonicalized(limits)?;
        Ok(canonical_hash(DOMAIN_QUOTIENT, &canonical))
    }
}

impl CanonicalEncode for QuotientMonitor {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.initial.0);
        encoder.u16(self.alphabet_size);
        encoder.u16(self.plant_state_count);
        encoder.usize(self.states.len());
        for state in &self.states {
            encoder.u16(state.id.0);
            state.semantics.encode(encoder);
        }
        encoder.usize(self.transitions.len());
        for transition in &self.transitions {
            encoder.u16(transition.from.0);
            encoder.u16(transition.symbol);
            encoder.u16(transition.to.0);
        }
        encoder.usize(self.projection.len());
        for projection in &self.projection {
            encoder.u16(projection.plant.0);
            encoder.u16(projection.quotient.0);
            projection.semantics.encode(encoder);
        }
    }
}

impl CanonicalEncode for QuotientLabel {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::NoAction => encoder.u8(0),
            Self::Action(action) => {
                encoder.u8(1);
                encoder.string(&action.service);
                encoder.string(&action.action);
                encoder.u32(action.public_bucket);
                encoder.u16(action.release_window_start);
                encoder.u16(action.release_deadline);
            }
        }
    }
}

fn validate_semantics(label: &QuotientLabel, limits: IrLimits) -> Result<(), IrError> {
    let QuotientLabel::Action(action) = label else {
        return Ok(());
    };
    if action.service.is_empty()
        || action.action.is_empty()
        || action.service.len() > limits.max_label_bytes
        || action.action.len() > limits.max_label_bytes
        || action.release_window_start > action.release_deadline
        || action.release_deadline >= limits.max_horizon
    {
        return Err(IrError::InvalidActionSemantics);
    }
    Ok(())
}
