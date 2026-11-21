//! Public-safe incident artifact with the shortest public counterexample.

use crate::sentinel_escalation::AssuranceResponse;
use crate::sentinel_retention::RetainedPublicStep;
use crate::sentinel_revocation::RevocationReason;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAssuranceIncidentCapsule {
    pub deployment_identity_digest: [u8; 32],
    pub evidence_digest: [u8; 32],
    pub reason: RevocationReason,
    pub response: AssuranceResponse,
    pub counterexample: Vec<RetainedPublicStep>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncidentCapsuleError {
    ZeroBinding,
    EmptyCounterexample,
    NonMonotonicSequence,
    CounterexampleTooLong,
}

impl PublicAssuranceIncidentCapsule {
    pub fn new(
        deployment_identity_digest: [u8; 32],
        evidence_digest: [u8; 32],
        reason: RevocationReason,
        response: AssuranceResponse,
        counterexample: Vec<RetainedPublicStep>,
    ) -> Result<Self, IncidentCapsuleError> {
        if deployment_identity_digest == [0; 32] || evidence_digest == [0; 32] {
            return Err(IncidentCapsuleError::ZeroBinding);
        }
        if counterexample.is_empty() {
            return Err(IncidentCapsuleError::EmptyCounterexample);
        }
        if counterexample.len() > 64 {
            return Err(IncidentCapsuleError::CounterexampleTooLong);
        }
        if counterexample
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(IncidentCapsuleError::NonMonotonicSequence);
        }
        Ok(Self {
            deployment_identity_digest,
            evidence_digest,
            reason,
            response,
            counterexample,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_carries_only_public_slot_and_action_state() {
        let step = RetainedPublicStep {
            sequence: 1,
            slot: 2,
            action_class: 3,
            public_state: 4,
        };
        let capsule = PublicAssuranceIncidentCapsule::new(
            [1; 32],
            [2; 32],
            RevocationReason::PrivacyViolation,
            AssuranceResponse::Quarantine,
            vec![step],
        )
        .unwrap();
        assert_eq!(capsule.counterexample, vec![step]);
    }
}
