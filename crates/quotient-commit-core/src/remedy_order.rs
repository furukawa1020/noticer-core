//! Total ordering that never trades safety for a cheaper patch.

use std::cmp::Ordering;

use crate::remedy_cost::RepairCost;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankedRepair {
    pub safety_verified: bool,
    pub semantics_preserved: bool,
    pub cost: RepairCost,
    pub canonical_bytes: Vec<u8>,
}

impl Ord for RankedRepair {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            !self.safety_verified,
            !self.semantics_preserved,
            self.cost.edits,
            self.cost.delay_slots,
            self.cost.semantic_distance,
            &self.canonical_bytes,
        )
            .cmp(&(
                !other.safety_verified,
                !other.semantics_preserved,
                other.cost.edits,
                other.cost.delay_slots,
                other.cost.semantic_distance,
                &other.canonical_bytes,
            ))
    }
}

impl PartialOrd for RankedRepair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranked(safe: bool, edits: u32) -> RankedRepair {
        RankedRepair {
            safety_verified: safe,
            semantics_preserved: true,
            cost: RepairCost {
                edits,
                delay_slots: 0,
                semantic_distance: 0,
            },
            canonical_bytes: vec![edits as u8],
        }
    }

    #[test]
    fn safety_precedes_cost() {
        assert!(ranked(true, 10) < ranked(false, 1));
    }

    #[test]
    fn canonical_bytes_break_exact_ties() {
        let mut left = ranked(true, 1);
        let mut right = ranked(true, 1);
        left.canonical_bytes = vec![1];
        right.canonical_bytes = vec![2];
        assert!(left < right);
    }
}
