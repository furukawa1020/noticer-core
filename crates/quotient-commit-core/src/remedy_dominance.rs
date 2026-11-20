//! Pareto dominance used only for sound repair-search pruning.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairMetrics {
    pub edits: u32,
    pub delay_slots: u32,
    pub semantic_distance: u32,
}

#[must_use]
pub const fn dominates(left: RepairMetrics, right: RepairMetrics) -> bool {
    let no_worse = left.edits <= right.edits
        && left.delay_slots <= right.delay_slots
        && left.semantic_distance <= right.semantic_distance;
    let strictly_better = left.edits < right.edits
        || left.delay_slots < right.delay_slots
        || left.semantic_distance < right.semantic_distance;
    no_worse && strictly_better
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_pareto_improvement_dominates() {
        let small = RepairMetrics {
            edits: 1,
            delay_slots: 0,
            semantic_distance: 0,
        };
        let large = RepairMetrics {
            edits: 2,
            delay_slots: 0,
            semantic_distance: 1,
        };
        assert!(dominates(small, large));
        assert!(!dominates(large, small));
    }

    #[test]
    fn tradeoffs_are_not_unsafely_pruned() {
        let fast = RepairMetrics {
            edits: 2,
            delay_slots: 0,
            semantic_distance: 0,
        };
        let small = RepairMetrics {
            edits: 1,
            delay_slots: 3,
            semantic_distance: 0,
        };
        assert!(!dominates(fast, small));
        assert!(!dominates(small, fast));
    }
}
