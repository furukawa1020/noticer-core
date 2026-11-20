//! Deterministic selection restricted to fully verified candidates.

use crate::remedy_order::RankedRepair;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectableRepair {
    pub candidate_id: u64,
    pub rank: RankedRepair,
    pub all_verifiers_passed: bool,
}

pub fn select(candidates: &[SelectableRepair]) -> Option<&SelectableRepair> {
    candidates
        .iter()
        .filter(|candidate| {
            candidate.all_verifiers_passed
                && candidate.rank.safety_verified
                && candidate.rank.semantics_preserved
        })
        .min_by(|left, right| {
            left.rank
                .cmp(&right.rank)
                .then_with(|| left.candidate_id.cmp(&right.candidate_id))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_cost::RepairCost;

    fn candidate(id: u64, edits: u32, verified: bool) -> SelectableRepair {
        SelectableRepair {
            candidate_id: id,
            rank: RankedRepair {
                safety_verified: true,
                semantics_preserved: true,
                cost: RepairCost {
                    edits,
                    delay_slots: 0,
                    semantic_distance: 0,
                },
                canonical_bytes: vec![id as u8],
            },
            all_verifiers_passed: verified,
        }
    }

    #[test]
    fn unverified_cheapest_candidate_is_never_selected() {
        let candidates = [candidate(1, 1, false), candidate(2, 2, true)];
        assert_eq!(select(&candidates).unwrap().candidate_id, 2);
    }
}
