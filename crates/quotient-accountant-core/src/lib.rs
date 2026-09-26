#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub const MAX_ALPHA_ORDERS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetKey {
    pub secret_family_hash: [u8; 32],
    pub coalition_hash: [u8; 32],
    pub action_quotient_hash: [u8; 32],
    pub secret_model_version: u64,
    pub policy_epoch: u64,
}

impl BudgetKey {
    pub const fn validate(self) -> Result<Self, CompositionError> {
        if all_zero(&self.secret_family_hash)
            || all_zero(&self.coalition_hash)
            || all_zero(&self.action_quotient_hash)
        {
            Err(CompositionError::InvalidBudgetKey)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalMomentBound {
    pub alpha: u16,
    pub log_moment_q64_64_upper: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedConditionalProfile {
    pub budget_key: BudgetKey,
    pub profile_hash: [u8; 32],
    pub validity_epoch: u64,
    pub moments: Vec<ConditionalMomentBound>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicSelectionEvidence {
    pub public_transcript_hash: [u8; 32],
    pub selected_before_release: bool,
    pub selector_uses_public_inputs_only: bool,
    pub coalition_in_scope: bool,
    pub profile_valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalReleaseStep {
    pub release_sequence: u64,
    pub profile: CertifiedConditionalProfile,
    pub selection: PublicSelectionEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposedMomentProfile {
    pub budget_key: BudgetKey,
    pub moments: Vec<ConditionalMomentBound>,
    pub releases: u64,
    pub last_profile_epoch: u64,
    pub last_public_transcript_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptiveComposer {
    state: ComposedMomentProfile,
}

impl AdaptiveComposer {
    pub fn new(
        budget_key: BudgetKey,
        alpha_orders: &[u16],
        initial_public_transcript_hash: [u8; 32],
    ) -> Result<Self, CompositionError> {
        budget_key.validate()?;
        validate_hash(initial_public_transcript_hash)?;
        validate_orders(alpha_orders)?;
        let moments = alpha_orders
            .iter()
            .map(|&alpha| ConditionalMomentBound {
                alpha,
                log_moment_q64_64_upper: 0,
            })
            .collect();
        Ok(Self {
            state: ComposedMomentProfile {
                budget_key,
                moments,
                releases: 0,
                last_profile_epoch: 0,
                last_public_transcript_hash: initial_public_transcript_hash,
            },
        })
    }

    pub fn compose(
        &mut self,
        step: &ConditionalReleaseStep,
    ) -> Result<&ComposedMomentProfile, CompositionError> {
        validate_step(&self.state, step)?;
        let mut next = self.state.moments.clone();
        for (total, increment) in next.iter_mut().zip(&step.profile.moments) {
            total.log_moment_q64_64_upper = total
                .log_moment_q64_64_upper
                .checked_add(increment.log_moment_q64_64_upper)
                .ok_or(CompositionError::ArithmeticOverflow)?;
        }
        self.state.moments = next;
        self.state.releases = self
            .state
            .releases
            .checked_add(1)
            .ok_or(CompositionError::ArithmeticOverflow)?;
        self.state.last_profile_epoch = step.profile.validity_epoch;
        self.state.last_public_transcript_hash = step.selection.public_transcript_hash;
        Ok(&self.state)
    }

    pub const fn state(&self) -> &ComposedMomentProfile {
        &self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionError {
    InvalidBudgetKey,
    ZeroHash,
    EmptyOrders,
    ResourceLimit,
    InvalidOrder,
    NonCanonicalOrders,
    IncompatibleBudgetKey,
    ProfileHashMissing,
    AlphaGridMismatch,
    ReleaseSequenceDiscontinuity,
    ProfileEpochRollback,
    ProfileSelectedAfterRelease,
    PrivateDependentSelection,
    CoalitionOutsideProfile,
    InvalidProfile,
    PublicTranscriptReplay,
    ArithmeticOverflow,
}

fn validate_step(
    state: &ComposedMomentProfile,
    step: &ConditionalReleaseStep,
) -> Result<(), CompositionError> {
    step.profile.budget_key.validate()?;
    if step.profile.budget_key != state.budget_key {
        return Err(CompositionError::IncompatibleBudgetKey);
    }
    validate_hash(step.profile.profile_hash).map_err(|_| CompositionError::ProfileHashMissing)?;
    validate_hash(step.selection.public_transcript_hash)?;
    if step.release_sequence != state.releases {
        return Err(CompositionError::ReleaseSequenceDiscontinuity);
    }
    if step.profile.validity_epoch < state.last_profile_epoch {
        return Err(CompositionError::ProfileEpochRollback);
    }
    if !step.selection.selected_before_release {
        return Err(CompositionError::ProfileSelectedAfterRelease);
    }
    if !step.selection.selector_uses_public_inputs_only {
        return Err(CompositionError::PrivateDependentSelection);
    }
    if !step.selection.coalition_in_scope {
        return Err(CompositionError::CoalitionOutsideProfile);
    }
    if !step.selection.profile_valid {
        return Err(CompositionError::InvalidProfile);
    }
    if step.selection.public_transcript_hash == state.last_public_transcript_hash {
        return Err(CompositionError::PublicTranscriptReplay);
    }
    if step.profile.moments.len() != state.moments.len()
        || step
            .profile
            .moments
            .iter()
            .zip(&state.moments)
            .any(|(profile, total)| profile.alpha != total.alpha)
    {
        return Err(CompositionError::AlphaGridMismatch);
    }
    Ok(())
}

fn validate_orders(orders: &[u16]) -> Result<(), CompositionError> {
    if orders.is_empty() {
        return Err(CompositionError::EmptyOrders);
    }
    if orders.len() > MAX_ALPHA_ORDERS {
        return Err(CompositionError::ResourceLimit);
    }
    let mut previous = 1;
    for &alpha in orders {
        if alpha <= 1 {
            return Err(CompositionError::InvalidOrder);
        }
        if alpha <= previous {
            return Err(CompositionError::NonCanonicalOrders);
        }
        previous = alpha;
    }
    Ok(())
}

const fn validate_hash(hash: [u8; 32]) -> Result<(), CompositionError> {
    if all_zero(&hash) {
        Err(CompositionError::ZeroHash)
    } else {
        Ok(())
    }
}

const fn all_zero(hash: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < hash.len() {
        if hash[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn key() -> BudgetKey {
        BudgetKey {
            secret_family_hash: [1; 32],
            coalition_hash: [2; 32],
            action_quotient_hash: [3; 32],
            secret_model_version: 4,
            policy_epoch: 5,
        }
    }

    fn step(sequence: u64, transcript: u8, values: [u128; 2]) -> ConditionalReleaseStep {
        ConditionalReleaseStep {
            release_sequence: sequence,
            profile: CertifiedConditionalProfile {
                budget_key: key(),
                profile_hash: [6; 32],
                validity_epoch: 7,
                moments: vec![
                    ConditionalMomentBound {
                        alpha: 2,
                        log_moment_q64_64_upper: values[0],
                    },
                    ConditionalMomentBound {
                        alpha: 4,
                        log_moment_q64_64_upper: values[1],
                    },
                ],
            },
            selection: PublicSelectionEvidence {
                public_transcript_hash: [transcript; 32],
                selected_before_release: true,
                selector_uses_public_inputs_only: true,
                coalition_in_scope: true,
                profile_valid: true,
            },
        }
    }

    fn composer() -> AdaptiveComposer {
        AdaptiveComposer::new(key(), &[2, 4], [9; 32]).unwrap()
    }

    #[test]
    fn sequential_conditional_profiles_add_monotonically() {
        let mut composer = composer();
        composer.compose(&step(0, 10, [3, 5])).unwrap();
        composer.compose(&step(1, 11, [7, 9])).unwrap();
        assert_eq!(composer.state().moments[0].log_moment_q64_64_upper, 10);
        assert_eq!(composer.state().moments[1].log_moment_q64_64_upper, 14);
        assert_eq!(composer.state().releases, 2);
    }

    #[test]
    fn exact_aetp_zero_profile_adds_no_cost() {
        let mut composer = composer();
        composer.compose(&step(0, 10, [0, 0])).unwrap();
        assert!(composer
            .state()
            .moments
            .iter()
            .all(|moment| moment.log_moment_q64_64_upper == 0));
    }

    #[test]
    fn incompatible_scope_and_alpha_grid_are_rejected() {
        let mut composer = composer();
        let mut incompatible = step(0, 10, [1, 1]);
        incompatible.profile.budget_key.policy_epoch += 1;
        assert_eq!(
            composer.compose(&incompatible),
            Err(CompositionError::IncompatibleBudgetKey)
        );
        let mut grid = step(0, 10, [1, 1]);
        grid.profile.moments[1].alpha = 8;
        assert_eq!(
            composer.compose(&grid),
            Err(CompositionError::AlphaGridMismatch)
        );
    }

    #[test]
    fn hidden_selection_and_late_profile_are_rejected() {
        let mut composer = composer();
        let mut private = step(0, 10, [1, 1]);
        private.selection.selector_uses_public_inputs_only = false;
        assert_eq!(
            composer.compose(&private),
            Err(CompositionError::PrivateDependentSelection)
        );
        let mut late = step(0, 10, [1, 1]);
        late.selection.selected_before_release = false;
        assert_eq!(
            composer.compose(&late),
            Err(CompositionError::ProfileSelectedAfterRelease)
        );
    }

    #[test]
    fn replay_discontinuity_and_epoch_rollback_fail_closed() {
        let mut composer = composer();
        composer.compose(&step(0, 10, [1, 1])).unwrap();
        assert_eq!(
            composer.compose(&step(2, 11, [1, 1])),
            Err(CompositionError::ReleaseSequenceDiscontinuity)
        );
        assert_eq!(
            composer.compose(&step(1, 10, [1, 1])),
            Err(CompositionError::PublicTranscriptReplay)
        );
        let mut old = step(1, 11, [1, 1]);
        old.profile.validity_epoch = 6;
        assert_eq!(
            composer.compose(&old),
            Err(CompositionError::ProfileEpochRollback)
        );
    }

    #[test]
    fn overflow_does_not_mutate_composed_state() {
        let mut composer = composer();
        composer
            .compose(&step(0, 10, [u128::MAX, u128::MAX]))
            .unwrap();
        let before = composer.state().clone();
        assert_eq!(
            composer.compose(&step(1, 11, [1, 1])),
            Err(CompositionError::ArithmeticOverflow)
        );
        assert_eq!(composer.state(), &before);
    }
}
