use crate::proof_fault_domain_label::{verify, FaultDomainLabel};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainRequirement {
    pub producers: usize,
    pub regions: usize,
    pub providers: usize,
    pub families: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainQuorumError {
    Authentication,
    DuplicateProducer,
    InsufficientProducers,
    InsufficientRegions,
    InsufficientProviders,
    InsufficientFamilies,
}
pub fn verify_quorum(
    labels: &[FaultDomainLabel],
    r: DomainRequirement,
    key: [u8; 32],
) -> Result<(), DomainQuorumError> {
    let mut producers = BTreeSet::new();
    let mut regions = BTreeSet::new();
    let mut providers = BTreeSet::new();
    let mut families = BTreeSet::new();
    for l in labels {
        if !verify(*l, key) {
            return Err(DomainQuorumError::Authentication);
        }
        if !producers.insert(l.producer) {
            return Err(DomainQuorumError::DuplicateProducer);
        }
        regions.insert(l.region);
        providers.insert(l.provider);
        families.insert(l.family);
    }
    if producers.len() < r.producers {
        return Err(DomainQuorumError::InsufficientProducers);
    }
    if regions.len() < r.regions {
        return Err(DomainQuorumError::InsufficientRegions);
    }
    if providers.len() < r.providers {
        return Err(DomainQuorumError::InsufficientProviders);
    }
    if families.len() < r.families {
        return Err(DomainQuorumError::InsufficientFamilies);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proof_fault_domain_label::issue, proof_producer_identity::ProducerFamily};
    const K: [u8; 32] = [6; 32];
    fn r() -> DomainRequirement {
        DomainRequirement {
            producers: 2,
            regions: 2,
            providers: 2,
            families: 2,
        }
    }
    #[test]
    fn accepts_cross_domain() {
        let a = issue([1; 16], 1, 1, ProducerFamily::Native, 1, K);
        let b = issue([2; 16], 2, 2, ProducerFamily::Wasm, 1, K);
        assert_eq!(verify_quorum(&[a, b], r(), K), Ok(()))
    }
    #[test]
    fn rejects_region_collapse() {
        let a = issue([1; 16], 1, 1, ProducerFamily::Native, 1, K);
        let b = issue([2; 16], 1, 2, ProducerFamily::Wasm, 1, K);
        assert_eq!(
            verify_quorum(&[a, b], r(), K),
            Err(DomainQuorumError::InsufficientRegions)
        );
    }
}
