#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Digest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MechanismId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MechanismCertificate {
    pub mechanism_id: MechanismId,
    pub public_context_digest: Digest,
    pub profile_digest: Digest,
    pub maximum_cost_q64_64: u128,
    pub public_utility_rank: u64,
}

impl MechanismCertificate {
    fn validate(self) -> Result<(), SelectorError> {
        if self.mechanism_id.0 == 0
            || self.public_context_digest.0 == [0; 32]
            || self.profile_digest.0 == [0; 32]
            || self.maximum_cost_q64_64 == 0
        {
            return Err(SelectorError::InvalidCertificate);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionDecision {
    pub decision_id: u64,
    pub mechanism_id: MechanismId,
    pub public_context_digest: Digest,
    pub profile_digest: Digest,
    pub certified_cost_q64_64: u128,
    pub public_utility_rank: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationSource {
    None,
    PublicContextChanged,
    PrivateEvidence,
}

#[derive(Debug)]
struct State {
    certificates: BTreeMap<MechanismId, MechanismCertificate>,
    decisions: BTreeMap<u64, SelectionDecision>,
}

#[derive(Debug)]
pub struct MechanismSelector {
    maximum_certificates: usize,
    maximum_decisions: usize,
    state: Mutex<State>,
}

impl MechanismSelector {
    pub fn new(
        maximum_certificates: usize,
        maximum_decisions: usize,
    ) -> Result<Self, SelectorError> {
        if maximum_certificates == 0 || maximum_decisions == 0 {
            return Err(SelectorError::InvalidConfig);
        }
        Ok(Self {
            maximum_certificates,
            maximum_decisions,
            state: Mutex::new(State {
                certificates: BTreeMap::new(),
                decisions: BTreeMap::new(),
            }),
        })
    }

    pub fn register(&self, certificate: MechanismCertificate) -> Result<(), SelectorError> {
        certificate.validate()?;
        let mut state = self.state.lock().map_err(|_| SelectorError::LockPoisoned)?;
        if state.certificates.contains_key(&certificate.mechanism_id) {
            return Err(SelectorError::MechanismAlreadyRegistered);
        }
        if state.certificates.len() >= self.maximum_certificates {
            return Err(SelectorError::ResourceLimitExceeded);
        }
        state
            .certificates
            .insert(certificate.mechanism_id, certificate);
        Ok(())
    }

    pub fn select(
        &self,
        decision_id: u64,
        public_context_digest: Digest,
        profile_digest: Digest,
        remaining_budget_q64_64: u128,
    ) -> Result<SelectionDecision, SelectorError> {
        if decision_id == 0 || public_context_digest.0 == [0; 32] || profile_digest.0 == [0; 32] {
            return Err(SelectorError::InvalidSelectionRequest);
        }
        let mut state = self.state.lock().map_err(|_| SelectorError::LockPoisoned)?;
        if state.decisions.contains_key(&decision_id) {
            return Err(SelectorError::DecisionIdAlreadyUsed);
        }
        if state.decisions.len() >= self.maximum_decisions {
            return Err(SelectorError::ResourceLimitExceeded);
        }
        let certificate = state
            .certificates
            .values()
            .filter(|certificate| {
                certificate.public_context_digest == public_context_digest
                    && certificate.profile_digest == profile_digest
                    && certificate.maximum_cost_q64_64 <= remaining_budget_q64_64
            })
            .max_by(|left, right| {
                left.public_utility_rank
                    .cmp(&right.public_utility_rank)
                    .then_with(|| right.mechanism_id.cmp(&left.mechanism_id))
            })
            .copied()
            .ok_or(SelectorError::NoCertifiedMechanism)?;
        let decision = SelectionDecision {
            decision_id,
            mechanism_id: certificate.mechanism_id,
            public_context_digest,
            profile_digest,
            certified_cost_q64_64: certificate.maximum_cost_q64_64,
            public_utility_rank: certificate.public_utility_rank,
        };
        state.decisions.insert(decision_id, decision);
        Ok(decision)
    }

    pub fn authorize_release(
        &self,
        decision_id: u64,
        mechanism_id: MechanismId,
        current_public_context_digest: Digest,
        current_profile_digest: Digest,
        mutation_source: MutationSource,
    ) -> Result<SelectionDecision, SelectorError> {
        match mutation_source {
            MutationSource::PrivateEvidence => {
                return Err(SelectorError::PrivateDependentMutationRejected)
            }
            MutationSource::PublicContextChanged => return Err(SelectorError::ReselectionRequired),
            MutationSource::None => {}
        }
        let state = self.state.lock().map_err(|_| SelectorError::LockPoisoned)?;
        let decision = state
            .decisions
            .get(&decision_id)
            .copied()
            .ok_or(SelectorError::UnknownDecision)?;
        if decision.mechanism_id != mechanism_id {
            return Err(SelectorError::MechanismMutationRejected);
        }
        if decision.public_context_digest != current_public_context_digest
            || decision.profile_digest != current_profile_digest
        {
            return Err(SelectorError::ReselectionRequired);
        }
        Ok(decision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorError {
    InvalidConfig,
    InvalidCertificate,
    InvalidSelectionRequest,
    MechanismAlreadyRegistered,
    DecisionIdAlreadyUsed,
    NoCertifiedMechanism,
    UnknownDecision,
    PrivateDependentMutationRejected,
    MechanismMutationRejected,
    ReselectionRequired,
    ResourceLimitExceeded,
    LockPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> Digest {
        Digest([value; 32])
    }
    fn selector() -> MechanismSelector {
        let selector = MechanismSelector::new(4, 4).unwrap();
        for (id, cost, utility) in [(1, 20, 4), (2, 40, 9), (3, 40, 9)] {
            selector
                .register(MechanismCertificate {
                    mechanism_id: MechanismId(id),
                    public_context_digest: digest(1),
                    profile_digest: digest(2),
                    maximum_cost_q64_64: cost,
                    public_utility_rank: utility,
                })
                .unwrap();
        }
        selector
    }

    #[test]
    fn chooses_highest_public_utility_with_stable_tie_break() {
        let decision = selector().select(1, digest(1), digest(2), 40).unwrap();
        assert_eq!(decision.mechanism_id, MechanismId(2));
    }

    #[test]
    fn budget_excludes_expensive_mechanisms() {
        let decision = selector().select(1, digest(1), digest(2), 20).unwrap();
        assert_eq!(decision.mechanism_id, MechanismId(1));
    }

    #[test]
    fn private_dependent_mutation_is_rejected() {
        let selector = selector();
        selector.select(1, digest(1), digest(2), 40).unwrap();
        assert_eq!(
            selector.authorize_release(
                1,
                MechanismId(1),
                digest(1),
                digest(2),
                MutationSource::PrivateEvidence
            ),
            Err(SelectorError::PrivateDependentMutationRejected)
        );
    }

    #[test]
    fn mechanism_or_public_context_mutation_requires_rejection() {
        let selector = selector();
        selector.select(1, digest(1), digest(2), 40).unwrap();
        assert_eq!(
            selector.authorize_release(
                1,
                MechanismId(3),
                digest(1),
                digest(2),
                MutationSource::None
            ),
            Err(SelectorError::MechanismMutationRejected)
        );
        assert_eq!(
            selector.authorize_release(
                1,
                MechanismId(2),
                digest(9),
                digest(2),
                MutationSource::None
            ),
            Err(SelectorError::ReselectionRequired)
        );
    }
}
