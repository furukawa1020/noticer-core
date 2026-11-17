//! Authenticated witness for a certified symmetry reduction.

use crate::{oracle_state_digest::digest, oracle_state_pair::StatePair, receipt::hmac_sha256};

const DOMAIN: &[u8] = b"noticer.oracle.symmetry-witness.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymmetryWitness {
    pub original_digest: [u8; 32],
    pub representative_digest: [u8; 32],
    pub relation_digest: [u8; 32],
    pub oracle_version: u32,
    authenticator: [u8; 32],
}

impl SymmetryWitness {
    pub fn issue(
        key: [u8; 32],
        original: &StatePair,
        representative: &StatePair,
        relation_digest: [u8; 32],
        oracle_version: u32,
    ) -> Self {
        let original_digest = digest(original);
        let representative_digest = digest(representative);
        let authenticator = authenticate(
            key,
            original_digest,
            representative_digest,
            relation_digest,
            oracle_version,
        );
        Self {
            original_digest,
            representative_digest,
            relation_digest,
            oracle_version,
            authenticator,
        }
    }

    pub fn verify(
        &self,
        key: [u8; 32],
        original: &StatePair,
        representative: &StatePair,
        expected_relation: [u8; 32],
        expected_version: u32,
    ) -> bool {
        let original_digest = digest(original);
        let representative_digest = digest(representative);
        self.original_digest == original_digest
            && self.representative_digest == representative_digest
            && self.relation_digest == expected_relation
            && self.oracle_version == expected_version
            && self.authenticator
                == authenticate(
                    key,
                    original_digest,
                    representative_digest,
                    expected_relation,
                    expected_version,
                )
    }
}

fn authenticate(
    key: [u8; 32],
    original: [u8; 32],
    representative: [u8; 32],
    relation: [u8; 32],
    version: u32,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 100);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&original);
    bytes.extend_from_slice(&representative);
    bytes.extend_from_slice(&relation);
    bytes.extend_from_slice(&version.to_be_bytes());
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(left: u8, right: u8) -> StatePair {
        StatePair {
            slot: 1,
            left: vec![left],
            right: vec![right],
        }
    }

    #[test]
    fn valid_witness_verifies() {
        let witness = SymmetryWitness::issue([5; 32], &pair(9, 1), &pair(1, 9), [3; 32], 2);
        assert!(witness.verify([5; 32], &pair(9, 1), &pair(1, 9), [3; 32], 2));
    }

    #[test]
    fn representative_substitution_is_rejected() {
        let witness = SymmetryWitness::issue([5; 32], &pair(9, 1), &pair(1, 9), [3; 32], 2);
        assert!(!witness.verify([5; 32], &pair(9, 1), &pair(2, 9), [3; 32], 2));
    }
}
