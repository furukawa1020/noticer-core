//! Public-safe capsule for communicating causal results.

use crate::{
    cause_redaction::RedactedCause,
    cause_verdict::{CausalInvalidReason, CausalityVerdict},
};

pub const CAPSULE_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicCauseCapsule {
    pub version: u16,
    pub verdict: CausalityVerdict,
    pub causes: Vec<RedactedCause>,
    pub model_digest: [u8; 32],
    pub certificate_authenticator: [u8; 32],
}

impl PublicCauseCapsule {
    pub fn create(
        verdict: CausalityVerdict,
        mut causes: Vec<RedactedCause>,
        model_digest: [u8; 32],
        certificate_authenticator: [u8; 32],
    ) -> Result<Self, CausalInvalidReason> {
        causes.sort_unstable();
        causes.dedup();
        if verdict.is_certified_causal() == causes.is_empty() {
            return Err(CausalInvalidReason::WitnessRejected);
        }
        Ok(Self {
            version: CAPSULE_VERSION,
            verdict,
            causes,
            model_digest,
            certificate_authenticator,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"noticer.quotient-cause.public-capsule.v1\0".to_vec();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(match self.verdict {
            CausalityVerdict::Causal { .. } => 0,
            CausalityVerdict::NonCausal { .. } => 1,
            CausalityVerdict::Invalid(_) => 2,
            CausalityVerdict::Inconclusive(_) => 3,
        });
        out.extend_from_slice(&(self.causes.len() as u64).to_be_bytes());
        for cause in &self.causes {
            out.extend_from_slice(&cause.slot.to_be_bytes());
            out.push(cause.kind_code);
            out.extend_from_slice(&cause.field_id.to_be_bytes());
        }
        out.extend_from_slice(&self.model_digest);
        out.extend_from_slice(&self.certificate_authenticator);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cause() -> RedactedCause {
        RedactedCause {
            slot: 2,
            kind_code: 1,
            field_id: 4,
        }
    }

    #[test]
    fn causal_capsule_requires_public_cause() {
        let verdict = CausalityVerdict::Causal {
            cause_size: 1,
            contingency_size: 0,
        };
        assert!(PublicCauseCapsule::create(verdict, vec![cause()], [1; 32], [2; 32]).is_ok());
        assert_eq!(
            PublicCauseCapsule::create(verdict, vec![], [1; 32], [2; 32]),
            Err(CausalInvalidReason::WitnessRejected)
        );
    }

    #[test]
    fn noncausal_capsule_cannot_smuggle_cause() {
        let verdict = CausalityVerdict::NonCausal {
            examined_interventions: 9,
        };
        assert_eq!(
            PublicCauseCapsule::create(verdict, vec![cause()], [1; 32], [2; 32]),
            Err(CausalInvalidReason::WitnessRejected)
        );
    }

    #[test]
    fn canonical_capsule_has_no_branch_value() {
        let verdict = CausalityVerdict::Causal {
            cause_size: 1,
            contingency_size: 0,
        };
        let capsule = PublicCauseCapsule::create(verdict, vec![cause()], [1; 32], [2; 32]).unwrap();
        assert!(!capsule.canonical_bytes().is_empty());
    }
}
