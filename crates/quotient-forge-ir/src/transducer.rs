use crate::canonical::{canonical_hash, CanonicalEncode, Encoder};
use crate::{FaultStateId, IrError, IrLimits, QuotientStateId, ReleaseStateId, DOMAIN_TRANSDUCER};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseState {
    pub id: ReleaseStateId,
}

/// This input intentionally has no private plant state or private value axis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReleaseInput {
    pub quotient: QuotientStateId,
    pub public_input: u16,
    pub fault: FaultStateId,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReleaseOutput {
    Cover,
    Action {
        action_class: QuotientStateId,
        release_slot: u16,
    },
    Delay,
    NormalizedFailure,
    Connect,
    Disconnect,
    PublicRetry {
        attempt: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseTransition {
    pub from: ReleaseStateId,
    pub input: ReleaseInput,
    pub to: ReleaseStateId,
    pub output: ReleaseOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseTransducer {
    pub states: Vec<ReleaseState>,
    pub initial: ReleaseStateId,
    pub quotient_state_count: u16,
    pub public_input_count: u16,
    pub fault_state_count: u16,
    pub horizon: u16,
    pub transitions: Vec<ReleaseTransition>,
}

impl ReleaseTransducer {
    pub fn validate(&self, limits: IrLimits) -> Result<(), IrError> {
        const COMPONENT: &str = "release transducer";
        if self.states.is_empty() {
            return Err(IrError::EmptyStates {
                component: COMPONENT,
            });
        }
        if self.states.len() > limits.max_states
            || self.transitions.len() > limits.max_transitions
            || self.horizon == 0
            || self.horizon > limits.max_horizon
        {
            return Err(IrError::LimitExceeded {
                component: COMPONENT,
            });
        }
        if self.quotient_state_count == 0
            || self.public_input_count == 0
            || self.fault_state_count == 0
        {
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
        let mut keys = BTreeSet::new();
        for transition in &self.transitions {
            if !ids.contains(&transition.from)
                || !ids.contains(&transition.to)
                || transition.input.quotient.0 >= self.quotient_state_count
                || transition.input.public_input >= self.public_input_count
                || transition.input.fault.0 >= self.fault_state_count
                || !output_is_valid(transition.output, self.quotient_state_count, self.horizon)
            {
                return Err(IrError::InvalidReference {
                    component: COMPONENT,
                });
            }
            if !keys.insert((transition.from, transition.input)) {
                return Err(IrError::Duplicate {
                    component: COMPONENT,
                });
            }
        }
        let expected = self
            .states
            .len()
            .checked_mul(usize::from(self.quotient_state_count))
            .and_then(|value| value.checked_mul(usize::from(self.public_input_count)))
            .and_then(|value| value.checked_mul(usize::from(self.fault_state_count)))
            .ok_or(IrError::LimitExceeded {
                component: COMPONENT,
            })?;
        if expected > limits.max_transitions {
            return Err(IrError::LimitExceeded {
                component: COMPONENT,
            });
        }
        if expected != self.transitions.len() {
            return Err(IrError::NonTotal {
                component: COMPONENT,
            });
        }
        Ok(())
    }

    pub fn canonicalized(&self, limits: IrLimits) -> Result<Self, IrError> {
        self.validate(limits)?;
        let mut outgoing: BTreeMap<ReleaseStateId, Vec<ReleaseTransition>> = BTreeMap::new();
        for transition in &self.transitions {
            outgoing
                .entry(transition.from)
                .or_default()
                .push(*transition);
        }
        for transitions in outgoing.values_mut() {
            transitions
                .sort_by_key(|transition| (transition.input, transition.output, transition.to));
        }
        let mut rename = BTreeMap::from([(self.initial, ReleaseStateId(0))]);
        let mut queue = VecDeque::from([self.initial]);
        while let Some(current) = queue.pop_front() {
            if let Some(transitions) = outgoing.get(&current) {
                for transition in transitions {
                    if !rename.contains_key(&transition.to) {
                        let next = ReleaseStateId(rename.len() as u16);
                        rename.insert(transition.to, next);
                        queue.push_back(transition.to);
                    }
                }
            }
        }
        let mut states: Vec<_> = rename.values().map(|id| ReleaseState { id: *id }).collect();
        states.sort_by_key(|state| state.id);
        let mut transitions = self
            .transitions
            .iter()
            .filter_map(|transition| {
                Some(ReleaseTransition {
                    from: *rename.get(&transition.from)?,
                    input: transition.input,
                    to: *rename.get(&transition.to)?,
                    output: transition.output,
                })
            })
            .collect::<Vec<_>>();
        transitions.sort_by_key(|transition| {
            (
                transition.from,
                transition.input,
                transition.output,
                transition.to,
            )
        });
        let canonical = Self {
            states,
            initial: ReleaseStateId(0),
            quotient_state_count: self.quotient_state_count,
            public_input_count: self.public_input_count,
            fault_state_count: self.fault_state_count,
            horizon: self.horizon,
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
        Ok(canonical_hash(DOMAIN_TRANSDUCER, &canonical))
    }
}

impl CanonicalEncode for ReleaseTransducer {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.initial.0);
        encoder.u16(self.quotient_state_count);
        encoder.u16(self.public_input_count);
        encoder.u16(self.fault_state_count);
        encoder.u16(self.horizon);
        encoder.usize(self.states.len());
        for state in &self.states {
            encoder.u16(state.id.0);
        }
        encoder.usize(self.transitions.len());
        for transition in &self.transitions {
            encoder.u16(transition.from.0);
            encoder.u16(transition.input.quotient.0);
            encoder.u16(transition.input.public_input);
            encoder.u16(transition.input.fault.0);
            encoder.u16(transition.to.0);
            transition.output.encode(encoder);
        }
    }
}

impl CanonicalEncode for ReleaseOutput {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Cover => encoder.u8(0),
            Self::Action {
                action_class,
                release_slot,
            } => {
                encoder.u8(1);
                encoder.u16(action_class.0);
                encoder.u16(*release_slot);
            }
            Self::Delay => encoder.u8(2),
            Self::NormalizedFailure => encoder.u8(3),
            Self::Connect => encoder.u8(4),
            Self::Disconnect => encoder.u8(5),
            Self::PublicRetry { attempt } => {
                encoder.u8(6);
                encoder.u16(*attempt);
            }
        }
    }
}

fn output_is_valid(output: ReleaseOutput, quotient_states: u16, horizon: u16) -> bool {
    match output {
        ReleaseOutput::Action {
            action_class,
            release_slot,
        } => action_class.0 < quotient_states && release_slot < horizon,
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostVector {
    pub dummy_frames: u64,
    pub total_frames: u64,
    pub worst_latency: u64,
    pub mean_latency_scaled: u64,
    pub state_count: u32,
    pub reconnects: u32,
    pub retries: u32,
    pub radio_on_slots: u64,
}

impl CostVector {
    pub fn lexicographic_cmp(&self, other: &Self) -> Ordering {
        (
            self.dummy_frames,
            self.worst_latency,
            self.state_count,
            self.reconnects,
            self.retries,
            self.total_frames,
            self.mean_latency_scaled,
            self.radio_on_slots,
        )
            .cmp(&(
                other.dummy_frames,
                other.worst_latency,
                other.state_count,
                other.reconnects,
                other.retries,
                other.total_frames,
                other.mean_latency_scaled,
                other.radio_on_slots,
            ))
    }
}

impl CanonicalEncode for CostVector {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.dummy_frames);
        encoder.u64(self.total_frames);
        encoder.u64(self.worst_latency);
        encoder.u64(self.mean_latency_scaled);
        encoder.u32(self.state_count);
        encoder.u32(self.reconnects);
        encoder.u32(self.retries);
        encoder.u64(self.radio_on_slots);
    }
}
