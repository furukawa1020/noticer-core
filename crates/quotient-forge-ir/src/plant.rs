use crate::canonical::{canonical_hash, CanonicalEncode, Encoder};
use crate::{IrError, IrLimits, PlantStateId, DOMAIN_PLANT};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlantState {
    pub id: PlantStateId,
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlantTransition {
    pub from: PlantStateId,
    pub private_input: u16,
    pub public_input: u16,
    pub to: PlantStateId,
    pub emitted_private_events: BTreeSet<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivatePlant {
    pub states: Vec<PlantState>,
    pub initial: PlantStateId,
    pub private_input_count: u16,
    pub public_input_count: u16,
    pub transitions: Vec<PlantTransition>,
}

impl PrivatePlant {
    pub fn validate(&self, limits: IrLimits) -> Result<(), IrError> {
        const COMPONENT: &str = "private plant";
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
        if self.private_input_count == 0 || self.public_input_count == 0 {
            return Err(IrError::InvalidReference {
                component: COMPONENT,
            });
        }
        let ids: BTreeSet<_> = self.states.iter().map(|state| state.id).collect();
        if ids.len() != self.states.len() {
            return Err(IrError::Duplicate {
                component: COMPONENT,
            });
        }
        if !ids.contains(&self.initial) {
            return Err(IrError::InvalidInitial {
                component: COMPONENT,
            });
        }
        if self
            .states
            .iter()
            .any(|state| state.label.is_empty() || state.label.len() > limits.max_label_bytes)
        {
            return Err(IrError::LimitExceeded {
                component: COMPONENT,
            });
        }
        let mut keys = BTreeSet::new();
        for transition in &self.transitions {
            if !ids.contains(&transition.from)
                || !ids.contains(&transition.to)
                || transition.private_input >= self.private_input_count
                || transition.public_input >= self.public_input_count
            {
                return Err(IrError::InvalidReference {
                    component: COMPONENT,
                });
            }
            if !keys.insert((
                transition.from,
                transition.private_input,
                transition.public_input,
            )) {
                return Err(IrError::Duplicate {
                    component: COMPONENT,
                });
            }
        }
        let expected = self
            .states
            .len()
            .checked_mul(usize::from(self.private_input_count))
            .and_then(|value| value.checked_mul(usize::from(self.public_input_count)))
            .ok_or(IrError::LimitExceeded {
                component: COMPONENT,
            })?;
        if expected != self.transitions.len() {
            return Err(IrError::NonTotal {
                component: COMPONENT,
            });
        }
        Ok(())
    }

    pub fn canonicalized(&self, limits: IrLimits) -> Result<Self, IrError> {
        self.validate(limits)?;
        let states: BTreeMap<_, _> = self.states.iter().map(|state| (state.id, state)).collect();
        let mut outgoing: BTreeMap<PlantStateId, Vec<&PlantTransition>> = BTreeMap::new();
        for transition in &self.transitions {
            outgoing
                .entry(transition.from)
                .or_default()
                .push(transition);
        }
        for transitions in outgoing.values_mut() {
            transitions.sort_by_key(|transition| {
                (
                    transition.private_input,
                    transition.public_input,
                    transition.to,
                    transition.emitted_private_events.clone(),
                )
            });
        }

        let mut rename = BTreeMap::from([(self.initial, PlantStateId(0))]);
        let mut queue = VecDeque::from([self.initial]);
        while let Some(current) = queue.pop_front() {
            if let Some(transitions) = outgoing.get(&current) {
                for transition in transitions {
                    if !rename.contains_key(&transition.to) {
                        let next = PlantStateId(rename.len() as u16);
                        rename.insert(transition.to, next);
                        queue.push_back(transition.to);
                    }
                }
            }
        }

        let mut canonical_states: Vec<_> = rename
            .iter()
            .map(|(old, new)| PlantState {
                id: *new,
                label: states[old].label.clone(),
            })
            .collect();
        canonical_states.sort_by_key(|state| state.id);
        let mut canonical_transitions = Vec::new();
        for transition in &self.transitions {
            let (Some(from), Some(to)) = (rename.get(&transition.from), rename.get(&transition.to))
            else {
                continue;
            };
            canonical_transitions.push(PlantTransition {
                from: *from,
                private_input: transition.private_input,
                public_input: transition.public_input,
                to: *to,
                emitted_private_events: transition.emitted_private_events.clone(),
            });
        }
        canonical_transitions.sort_by_key(|transition| {
            (
                transition.from,
                transition.private_input,
                transition.public_input,
                transition.to,
                transition.emitted_private_events.clone(),
            )
        });
        let canonical = Self {
            states: canonical_states,
            initial: PlantStateId(0),
            private_input_count: self.private_input_count,
            public_input_count: self.public_input_count,
            transitions: canonical_transitions,
        };
        canonical.validate(limits)?;
        Ok(canonical)
    }

    pub fn is_canonical(&self, limits: IrLimits) -> Result<bool, IrError> {
        Ok(self == &self.canonicalized(limits)?)
    }

    pub fn canonical_hash(&self, limits: IrLimits) -> Result<[u8; 32], IrError> {
        let canonical = self.canonicalized(limits)?;
        Ok(canonical_hash(DOMAIN_PLANT, &canonical))
    }
}

impl CanonicalEncode for PrivatePlant {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.initial.0);
        encoder.u16(self.private_input_count);
        encoder.u16(self.public_input_count);
        encoder.usize(self.states.len());
        for state in &self.states {
            encoder.u16(state.id.0);
            encoder.string(&state.label);
        }
        encoder.usize(self.transitions.len());
        for transition in &self.transitions {
            encoder.u16(transition.from.0);
            encoder.u16(transition.private_input);
            encoder.u16(transition.public_input);
            encoder.u16(transition.to.0);
            encoder.usize(transition.emitted_private_events.len());
            for event in &transition.emitted_private_events {
                encoder.u16(*event);
            }
        }
    }
}
