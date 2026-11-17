use crate::{
    proof_independence_policy::IndependencePolicy, proof_producer_identity::ProducerFamily,
};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerVote {
    pub producer: [u8; 16],
    pub family: ProducerFamily,
    pub evidence_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumError {
    DuplicateProducer,
    FamilyDenied,
    DigestMismatch,
    InsufficientVotes,
    InsufficientFamilies,
}
pub fn verify(
    votes: &[ProducerVote],
    digest: [u8; 32],
    threshold: usize,
    policy: &IndependencePolicy,
) -> Result<(), QuorumError> {
    let allowed = policy
        .allowed_families
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut producers = BTreeSet::new();
    let mut families = BTreeSet::new();
    for v in votes {
        if !producers.insert(v.producer) {
            return Err(QuorumError::DuplicateProducer);
        }
        if !allowed.contains(&v.family) {
            return Err(QuorumError::FamilyDenied);
        }
        if v.evidence_digest != digest {
            return Err(QuorumError::DigestMismatch);
        }
        families.insert(v.family);
    }
    if producers.len() < threshold {
        return Err(QuorumError::InsufficientVotes);
    }
    if families.len() < policy.minimum_families {
        return Err(QuorumError::InsufficientFamilies);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_independence_policy::compile;
    fn v(id: u8, f: ProducerFamily) -> ProducerVote {
        ProducerVote {
            producer: [id; 16],
            family: f,
            evidence_digest: [9; 32],
        }
    }
    #[test]
    fn accepts_independent_quorum() {
        let p = compile(&[ProducerFamily::Native, ProducerFamily::Wasm], 2).unwrap();
        assert_eq!(
            verify(
                &[v(1, ProducerFamily::Native), v(2, ProducerFamily::Wasm)],
                [9; 32],
                2,
                &p
            ),
            Ok(())
        )
    }
    #[test]
    fn rejects_monoculture() {
        let p = compile(&[ProducerFamily::Native, ProducerFamily::Wasm], 2).unwrap();
        assert_eq!(
            verify(
                &[v(1, ProducerFamily::Native), v(2, ProducerFamily::Native)],
                [9; 32],
                2,
                &p
            ),
            Err(QuorumError::InsufficientFamilies)
        )
    }
}
