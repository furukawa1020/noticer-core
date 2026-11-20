//! One-way mapping that prevents exhausted searches from claiming success.

use crate::remedy_budget::BudgetError;
use crate::remedy_verdict::{InconclusiveRepair, InvalidRepair, RepairVerdict};

#[must_use]
pub const fn classify_budget(error: BudgetError) -> RepairVerdict {
    match error {
        BudgetError::NodeLimit => RepairVerdict::Inconclusive(InconclusiveRepair::NodeLimit),
        BudgetError::WorldLimit => RepairVerdict::Inconclusive(InconclusiveRepair::WorldLimit),
        BudgetError::ZeroLimit => RepairVerdict::Invalid(InvalidRepair::ContradictoryConstraint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustion_can_never_be_repaired_or_unrepairable() {
        for error in [BudgetError::NodeLimit, BudgetError::WorldLimit] {
            let verdict = classify_budget(error);
            assert!(!verdict.deployment_allowed());
            assert!(!verdict.is_terminal_evidence());
        }
    }

    #[test]
    fn zero_budget_is_invalid_input() {
        assert_eq!(
            classify_budget(BudgetError::ZeroLimit),
            RepairVerdict::Invalid(InvalidRepair::ContradictoryConstraint)
        );
    }
}
