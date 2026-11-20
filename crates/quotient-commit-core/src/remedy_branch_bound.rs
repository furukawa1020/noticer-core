//! Auditable branch-and-bound selection over prevalidated repair candidates.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedCandidate {
    pub candidate_id: u64,
    pub lower_bound: u64,
    pub verified_cost: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchAndBoundResult {
    pub winner: Option<BoundedCandidate>,
    pub explored: u32,
    pub pruned: u32,
}

pub fn select(candidates: &[BoundedCandidate]) -> BranchAndBoundResult {
    let mut ordered = candidates.to_vec();
    ordered.sort_by_key(|candidate| (candidate.lower_bound, candidate.candidate_id));
    let mut winner: Option<BoundedCandidate> = None;
    let mut explored = 0_u32;
    let mut pruned = 0_u32;
    for candidate in ordered {
        let incumbent = winner.and_then(|value| value.verified_cost);
        if incumbent.is_some_and(|cost| candidate.lower_bound >= cost) {
            pruned += 1;
            continue;
        }
        explored += 1;
        let Some(cost) = candidate.verified_cost else {
            continue;
        };
        if cost < candidate.lower_bound {
            continue;
        }
        if incumbent.is_none_or(|best| cost < best) {
            winner = Some(candidate);
        }
    }
    BranchAndBoundResult {
        winner,
        explored,
        pruned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_bound_prunes_only_non_improving_candidates() {
        let result = select(&[
            BoundedCandidate {
                candidate_id: 2,
                lower_bound: 9,
                verified_cost: Some(10),
            },
            BoundedCandidate {
                candidate_id: 1,
                lower_bound: 2,
                verified_cost: Some(4),
            },
            BoundedCandidate {
                candidate_id: 3,
                lower_bound: 4,
                verified_cost: Some(4),
            },
        ]);
        assert_eq!(result.winner.unwrap().candidate_id, 1);
        assert_eq!(result.pruned, 2);
    }
}
