//! Canonical soundness certificate for a bounded causal verdict.

use crate::cause_verdict::{CausalInvalidReason, CausalityVerdict};

pub const CERTIFICATE_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalityCertificate {
    pub version: u16,
    pub model_digest: [u8; 32],
    pub actual_world_digest: [u8; 32],
    pub witness_digest: [u8; 32],
    pub predicate_code: u8,
    pub explored_worlds: u64,
    pub replay_digests: [[u8; 32]; 2],
    pub verdict: CausalityVerdict,
}

impl CausalityCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        model_digest: [u8; 32],
        actual_world_digest: [u8; 32],
        witness_digest: [u8; 32],
        predicate_code: u8,
        explored_worlds: u64,
        replay_digests: [[u8; 32]; 2],
        verdict: CausalityVerdict,
    ) -> Result<Self, CausalInvalidReason> {
        if matches!(verdict, CausalityVerdict::Causal { cause_size: 0, .. })
            || (verdict.is_certified_causal() && replay_digests[0] != replay_digests[1])
        {
            return Err(CausalInvalidReason::WitnessRejected);
        }
        Ok(Self {
            version: CERTIFICATE_VERSION,
            model_digest,
            actual_world_digest,
            witness_digest,
            predicate_code,
            explored_worlds,
            replay_digests,
            verdict,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"noticer.quotient-cause.certificate.v1\0".to_vec();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.model_digest);
        out.extend_from_slice(&self.actual_world_digest);
        out.extend_from_slice(&self.witness_digest);
        out.push(self.predicate_code);
        out.extend_from_slice(&self.explored_worlds.to_be_bytes());
        out.extend_from_slice(&self.replay_digests[0]);
        out.extend_from_slice(&self.replay_digests[1]);
        encode_verdict(self.verdict, &mut out);
        out
    }
}

fn encode_verdict(verdict: CausalityVerdict, out: &mut Vec<u8>) {
    match verdict {
        CausalityVerdict::Causal {
            cause_size,
            contingency_size,
        } => {
            out.push(0);
            out.extend_from_slice(&cause_size.to_be_bytes());
            out.extend_from_slice(&contingency_size.to_be_bytes());
        }
        CausalityVerdict::NonCausal {
            examined_interventions,
        } => {
            out.push(1);
            out.extend_from_slice(&examined_interventions.to_be_bytes());
        }
        CausalityVerdict::Invalid(reason) => {
            out.push(2);
            out.push(reason as u8);
        }
        CausalityVerdict::Inconclusive(reason) => {
            out.push(3);
            out.push(reason as u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_verdict::CausalInconclusiveReason;

    #[test]
    fn matching_replays_create_causal_certificate() {
        let verdict = CausalityVerdict::Causal {
            cause_size: 1,
            contingency_size: 0,
        };
        let certificate = CausalityCertificate::create(
            [1; 32],
            [2; 32],
            [3; 32],
            1,
            8,
            [[4; 32], [4; 32]],
            verdict,
        )
        .unwrap();
        assert!(!certificate.canonical_bytes().is_empty());
    }

    #[test]
    fn replay_disagreement_cannot_certify_causal() {
        let verdict = CausalityVerdict::Causal {
            cause_size: 1,
            contingency_size: 0,
        };
        assert_eq!(
            CausalityCertificate::create(
                [1; 32],
                [2; 32],
                [3; 32],
                1,
                8,
                [[4; 32], [5; 32]],
                verdict
            ),
            Err(CausalInvalidReason::WitnessRejected)
        );
    }

    #[test]
    fn inconclusive_remains_encodable() {
        let verdict = CausalityVerdict::Inconclusive(CausalInconclusiveReason::NodeLimit);
        assert!(CausalityCertificate::create(
            [1; 32],
            [2; 32],
            [0; 32],
            1,
            8,
            [[0; 32], [0; 32]],
            verdict
        )
        .is_ok());
    }
}
