#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Digest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileDescriptor {
    pub profile_id: Digest,
    pub schema_digest: Digest,
    pub policy_digest: Digest,
    pub model_digest: Digest,
    pub mechanism_digest: Digest,
    pub alpha_grid_digest: Digest,
    pub public_state: u64,
    pub generation: u64,
}

impl ProfileDescriptor {
    pub fn validate(self) -> Result<(), HandoffError> {
        if self.profile_id.0 == [0; 32]
            || self.schema_digest.0 == [0; 32]
            || self.policy_digest.0 == [0; 32]
            || self.model_digest.0 == [0; 32]
            || self.mechanism_digest.0 == [0; 32]
            || self.alpha_grid_digest.0 == [0; 32]
            || self.public_state == 0
            || self.generation == 0
        {
            return Err(HandoffError::InvalidDescriptor);
        }
        Ok(())
    }

    #[must_use]
    pub fn protected_dimensions_equal(self, other: Self) -> bool {
        self.schema_digest.0 == other.schema_digest.0
            && self.policy_digest.0 == other.policy_digest.0
            && self.model_digest.0 == other.model_digest.0
            && self.mechanism_digest.0 == other.mechanism_digest.0
            && self.alpha_grid_digest.0 == other.alpha_grid_digest.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationKind {
    Initial,
    CompatiblePublicHandoff,
    InvalidatingRebootstrap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationReceipt {
    pub sequence: u64,
    pub profile_id: Digest,
    pub generation: u64,
    pub kind: ActivationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffReceipt {
    pub sequence: u64,
    pub handoff_id: u64,
    pub from_profile_id: Digest,
    pub to_profile_id: Digest,
    pub boundary_trace_commitment: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryConfig {
    pub maximum_profiles: usize,
    pub maximum_public_transitions: usize,
    pub maximum_handoff_ids: usize,
}

impl RegistryConfig {
    pub const fn validate(self) -> Result<(), HandoffError> {
        if self.maximum_profiles == 0
            || self.maximum_public_transitions == 0
            || self.maximum_handoff_ids == 0
        {
            return Err(HandoffError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct State {
    sequence: u64,
    active_profile_id: Option<Digest>,
    profiles: BTreeMap<Digest, ProfileDescriptor>,
    invalidated_profiles: BTreeSet<Digest>,
    allowed_public_transitions: BTreeSet<(u64, u64)>,
    consumed_handoff_ids: BTreeSet<u64>,
}

#[derive(Debug)]
pub struct ProfileHandoffRegistry {
    config: RegistryConfig,
    state: Mutex<State>,
}

impl ProfileHandoffRegistry {
    pub fn new(config: RegistryConfig) -> Result<Self, HandoffError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(State {
                sequence: 0,
                active_profile_id: None,
                profiles: BTreeMap::new(),
                invalidated_profiles: BTreeSet::new(),
                allowed_public_transitions: BTreeSet::new(),
                consumed_handoff_ids: BTreeSet::new(),
            }),
        })
    }

    pub fn allow_public_transition(&self, from: u64, to: u64) -> Result<u64, HandoffError> {
        if from == 0 || to == 0 || from == to {
            return Err(HandoffError::InvalidPublicTransition);
        }
        let mut state = self.state.lock().map_err(|_| HandoffError::LockPoisoned)?;
        if state.allowed_public_transitions.len() >= self.config.maximum_public_transitions {
            return Err(HandoffError::ResourceLimitExceeded);
        }
        if !state.allowed_public_transitions.insert((from, to)) {
            return Err(HandoffError::PublicTransitionAlreadyDeclared);
        }
        state.sequence = next_sequence(state.sequence)?;
        Ok(state.sequence)
    }

    pub fn activate(
        &self,
        descriptor: ProfileDescriptor,
    ) -> Result<ActivationReceipt, HandoffError> {
        descriptor.validate()?;
        let mut state = self.state.lock().map_err(|_| HandoffError::LockPoisoned)?;
        if state.profiles.contains_key(&descriptor.profile_id) {
            return Err(HandoffError::ProfileIdAlreadyUsed);
        }
        if state.profiles.len() >= self.config.maximum_profiles {
            return Err(HandoffError::ResourceLimitExceeded);
        }
        let previous = state
            .active_profile_id
            .and_then(|profile_id| state.profiles.get(&profile_id).copied());
        let kind = match previous {
            None => ActivationKind::Initial,
            Some(current) => {
                let expected_generation = current
                    .generation
                    .checked_add(1)
                    .ok_or(HandoffError::ArithmeticOverflow)?;
                if descriptor.generation != expected_generation {
                    return Err(HandoffError::GenerationMismatch);
                }
                if current.protected_dimensions_equal(descriptor) {
                    if current.public_state != descriptor.public_state
                        && !state
                            .allowed_public_transitions
                            .contains(&(current.public_state, descriptor.public_state))
                    {
                        return Err(HandoffError::PublicTransitionNotAllowed);
                    }
                    ActivationKind::CompatiblePublicHandoff
                } else {
                    ActivationKind::InvalidatingRebootstrap
                }
            }
        };
        let sequence = next_sequence(state.sequence)?;
        if kind == ActivationKind::InvalidatingRebootstrap {
            if let Some(current) = previous {
                state.invalidated_profiles.insert(current.profile_id);
            }
        }
        state.profiles.insert(descriptor.profile_id, descriptor);
        state.active_profile_id = Some(descriptor.profile_id);
        state.sequence = sequence;
        Ok(ActivationReceipt {
            sequence,
            profile_id: descriptor.profile_id,
            generation: descriptor.generation,
            kind,
        })
    }

    pub fn accept_handoff(
        &self,
        handoff_id: u64,
        from_profile_id: Digest,
        to_profile_id: Digest,
        boundary_trace_commitment: Digest,
    ) -> Result<HandoffReceipt, HandoffError> {
        if handoff_id == 0 || boundary_trace_commitment.0 == [0; 32] {
            return Err(HandoffError::InvalidHandoff);
        }
        let mut state = self.state.lock().map_err(|_| HandoffError::LockPoisoned)?;
        if state.consumed_handoff_ids.contains(&handoff_id) {
            return Err(HandoffError::HandoffIdAlreadyUsed);
        }
        if state.consumed_handoff_ids.len() >= self.config.maximum_handoff_ids {
            return Err(HandoffError::ResourceLimitExceeded);
        }
        if state.active_profile_id != Some(to_profile_id) {
            return Err(HandoffError::TargetProfileNotActive);
        }
        validate_pair(&state, from_profile_id, to_profile_id)?;
        let sequence = next_sequence(state.sequence)?;
        state.consumed_handoff_ids.insert(handoff_id);
        state.sequence = sequence;
        Ok(HandoffReceipt {
            sequence,
            handoff_id,
            from_profile_id,
            to_profile_id,
            boundary_trace_commitment,
        })
    }

    pub fn validate_composition(
        &self,
        left_profile_id: Digest,
        right_profile_id: Digest,
    ) -> Result<(), HandoffError> {
        let state = self.state.lock().map_err(|_| HandoffError::LockPoisoned)?;
        validate_pair(&state, left_profile_id, right_profile_id)
    }

    pub fn active_profile(&self) -> Result<Option<ProfileDescriptor>, HandoffError> {
        let state = self.state.lock().map_err(|_| HandoffError::LockPoisoned)?;
        Ok(state
            .active_profile_id
            .and_then(|profile_id| state.profiles.get(&profile_id).copied()))
    }
}

fn validate_pair(
    state: &State,
    left_profile_id: Digest,
    right_profile_id: Digest,
) -> Result<(), HandoffError> {
    if state.invalidated_profiles.contains(&left_profile_id)
        || state.invalidated_profiles.contains(&right_profile_id)
    {
        return Err(HandoffError::ProfileInvalidated);
    }
    let left = state
        .profiles
        .get(&left_profile_id)
        .copied()
        .ok_or(HandoffError::UnknownProfile)?;
    let right = state
        .profiles
        .get(&right_profile_id)
        .copied()
        .ok_or(HandoffError::UnknownProfile)?;
    if !left.protected_dimensions_equal(right) {
        return Err(HandoffError::ProtectedDimensionMismatch);
    }
    if left.public_state != right.public_state
        && !state
            .allowed_public_transitions
            .contains(&(left.public_state, right.public_state))
    {
        return Err(HandoffError::PublicTransitionNotAllowed);
    }
    Ok(())
}

fn next_sequence(sequence: u64) -> Result<u64, HandoffError> {
    sequence
        .checked_add(1)
        .ok_or(HandoffError::ArithmeticOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    InvalidConfig,
    InvalidDescriptor,
    InvalidPublicTransition,
    InvalidHandoff,
    PublicTransitionAlreadyDeclared,
    PublicTransitionNotAllowed,
    ProfileIdAlreadyUsed,
    ProfileInvalidated,
    UnknownProfile,
    TargetProfileNotActive,
    ProtectedDimensionMismatch,
    GenerationMismatch,
    HandoffIdAlreadyUsed,
    ResourceLimitExceeded,
    ArithmeticOverflow,
    LockPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> Digest {
        Digest([value; 32])
    }

    fn descriptor(profile: u8, model: u8, public_state: u64, generation: u64) -> ProfileDescriptor {
        ProfileDescriptor {
            profile_id: digest(profile),
            schema_digest: digest(10),
            policy_digest: digest(11),
            model_digest: digest(model),
            mechanism_digest: digest(13),
            alpha_grid_digest: digest(14),
            public_state,
            generation,
        }
    }

    fn registry() -> ProfileHandoffRegistry {
        ProfileHandoffRegistry::new(RegistryConfig {
            maximum_profiles: 8,
            maximum_public_transitions: 8,
            maximum_handoff_ids: 8,
        })
        .unwrap()
    }

    #[test]
    fn declared_public_handoff_remains_composable() {
        let registry = registry();
        registry.allow_public_transition(1, 2).unwrap();
        registry.activate(descriptor(1, 12, 1, 1)).unwrap();
        let activation = registry.activate(descriptor(2, 12, 2, 2)).unwrap();
        assert_eq!(activation.kind, ActivationKind::CompatiblePublicHandoff);
        registry.validate_composition(digest(1), digest(2)).unwrap();
        registry
            .accept_handoff(1, digest(1), digest(2), digest(90))
            .unwrap();
    }

    #[test]
    fn model_change_invalidates_previous_profile() {
        let registry = registry();
        registry.activate(descriptor(1, 12, 1, 1)).unwrap();
        let activation = registry.activate(descriptor(2, 99, 1, 2)).unwrap();
        assert_eq!(activation.kind, ActivationKind::InvalidatingRebootstrap);
        assert_eq!(
            registry.validate_composition(digest(1), digest(2)),
            Err(HandoffError::ProfileInvalidated)
        );
        assert_eq!(
            registry.accept_handoff(1, digest(1), digest(2), digest(90)),
            Err(HandoffError::ProfileInvalidated)
        );
    }

    #[test]
    fn undeclared_public_transition_does_not_change_active_profile() {
        let registry = registry();
        registry.activate(descriptor(1, 12, 1, 1)).unwrap();
        assert_eq!(
            registry.activate(descriptor(2, 12, 2, 2)),
            Err(HandoffError::PublicTransitionNotAllowed)
        );
        assert_eq!(
            registry.active_profile().unwrap().unwrap().profile_id,
            digest(1)
        );
    }

    #[test]
    fn handoff_ids_are_single_use() {
        let registry = registry();
        registry.activate(descriptor(1, 12, 1, 1)).unwrap();
        registry.activate(descriptor(2, 12, 1, 2)).unwrap();
        registry
            .accept_handoff(1, digest(1), digest(2), digest(90))
            .unwrap();
        assert_eq!(
            registry.accept_handoff(1, digest(1), digest(2), digest(91)),
            Err(HandoffError::HandoffIdAlreadyUsed)
        );
    }

    #[test]
    fn skipped_generation_is_rejected() {
        let registry = registry();
        registry.activate(descriptor(1, 12, 1, 1)).unwrap();
        assert_eq!(
            registry.activate(descriptor(2, 12, 1, 3)),
            Err(HandoffError::GenerationMismatch)
        );
    }
}
