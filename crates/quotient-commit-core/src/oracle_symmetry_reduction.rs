//! Policy-gated symmetry reduction for ordered oracle state pairs.

use crate::oracle_state_pair::StatePair;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymmetryPolicy {
    PreserveOrder,
    CertifiedLeftRightEquivalent { relation_digest: [u8; 32] },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction {
    pub representative: StatePair,
    pub reduced: bool,
    pub relation_digest: Option<[u8; 32]>,
}

/// Selects a canonical representative only under an explicit symmetry policy.
pub fn reduce(pair: &StatePair, policy: SymmetryPolicy) -> Reduction {
    match policy {
        SymmetryPolicy::PreserveOrder => Reduction {
            representative: pair.clone(),
            reduced: false,
            relation_digest: None,
        },
        SymmetryPolicy::CertifiedLeftRightEquivalent { relation_digest } => {
            let swapped = StatePair {
                slot: pair.slot,
                left: pair.right.clone(),
                right: pair.left.clone(),
            };
            let representative = pair.clone().min(swapped);
            Reduction {
                reduced: representative != *pair,
                representative,
                relation_digest: Some(relation_digest),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(left: u8, right: u8) -> StatePair {
        StatePair {
            slot: 3,
            left: vec![left],
            right: vec![right],
        }
    }

    #[test]
    fn uncertified_relation_preserves_order() {
        let original = pair(9, 1);
        let result = reduce(&original, SymmetryPolicy::PreserveOrder);
        assert_eq!(result.representative, original);
        assert!(!result.reduced);
    }

    #[test]
    fn certified_relation_uses_canonical_orientation() {
        let result = reduce(
            &pair(9, 1),
            SymmetryPolicy::CertifiedLeftRightEquivalent {
                relation_digest: [4; 32],
            },
        );
        assert_eq!(result.representative, pair(1, 9));
        assert!(result.reduced);
        assert_eq!(result.relation_digest, Some([4; 32]));
    }
}
