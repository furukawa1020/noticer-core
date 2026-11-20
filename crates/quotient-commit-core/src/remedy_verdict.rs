//! Fail-closed verdicts for counterfactual remediation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidRepair {
    MalformedInput,
    BoundaryViolation,
    ContradictoryConstraint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InconclusiveRepair {
    NodeLimit,
    WorldLimit,
    Deadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairVerdict {
    Repaired,
    Unrepairable,
    Invalid(InvalidRepair),
    Inconclusive(InconclusiveRepair),
}

impl RepairVerdict {
    #[must_use]
    pub const fn deployment_allowed(self) -> bool {
        matches!(self, Self::Repaired)
    }

    #[must_use]
    pub const fn is_terminal_evidence(self) -> bool {
        matches!(self, Self::Repaired | Self::Unrepairable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_repaired_is_deployable() {
        assert!(RepairVerdict::Repaired.deployment_allowed());
        assert!(!RepairVerdict::Unrepairable.deployment_allowed());
        assert!(!RepairVerdict::Invalid(InvalidRepair::MalformedInput).deployment_allowed());
        assert!(!RepairVerdict::Inconclusive(InconclusiveRepair::NodeLimit).deployment_allowed());
    }

    #[test]
    fn invalid_and_inconclusive_are_not_promoted_to_evidence() {
        assert!(!RepairVerdict::Invalid(InvalidRepair::BoundaryViolation).is_terminal_evidence());
        assert!(!RepairVerdict::Inconclusive(InconclusiveRepair::Deadline).is_terminal_evidence());
    }
}
