//! Explicit TCB boundary for automated remediation.

use std::collections::BTreeSet;

use crate::remedy_set::RepairSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairPolicyBoundary {
    allowed_targets: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundaryError {
    EmptyBoundary,
    OutsideBoundary(String),
}

impl RepairPolicyBoundary {
    pub fn new(targets: impl IntoIterator<Item = String>) -> Result<Self, BoundaryError> {
        let allowed_targets: BTreeSet<_> = targets.into_iter().collect();
        if allowed_targets.is_empty() {
            return Err(BoundaryError::EmptyBoundary);
        }
        Ok(Self { allowed_targets })
    }

    pub fn validate(&self, repairs: &RepairSet) -> Result<(), BoundaryError> {
        for edit in repairs.edits() {
            if !self.allowed_targets.contains(edit.atom.target()) {
                return Err(BoundaryError::OutsideBoundary(
                    edit.atom.target().to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_atom::RepairAtom;
    use crate::remedy_patch_operation::PatchOperation;
    use crate::remedy_set::RepairEdit;

    #[test]
    fn tcb_external_target_is_rejected() {
        let boundary = RepairPolicyBoundary::new(["release_gate".to_owned()]).unwrap();
        let set = RepairSet::new(vec![RepairEdit {
            atom: RepairAtom::new(1, "network").unwrap(),
            operation: PatchOperation::Disable,
        }])
        .unwrap();
        assert_eq!(
            boundary.validate(&set),
            Err(BoundaryError::OutsideBoundary("network".to_owned()))
        );
    }
}
