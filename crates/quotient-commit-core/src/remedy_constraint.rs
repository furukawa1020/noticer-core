//! Fail-closed constraints over the repair search space.

use crate::remedy_patch_operation::PatchOperation;
use crate::remedy_set::RepairSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowedOperations(u8);

impl AllowedOperations {
    pub const DISABLE: u8 = 1;
    pub const SUBSTITUTE: u8 = 2;
    pub const CLAMP: u8 = 4;
    pub const DELAY: u8 = 8;

    pub fn new(bits: u8) -> Result<Self, ConstraintError> {
        if bits == 0 || bits & !0x0f != 0 {
            return Err(ConstraintError::InvalidOperationMask);
        }
        Ok(Self(bits))
    }

    #[must_use]
    pub const fn permits(self, operation: PatchOperation) -> bool {
        let bit = match operation {
            PatchOperation::Disable => Self::DISABLE,
            PatchOperation::Substitute { .. } => Self::SUBSTITUTE,
            PatchOperation::Clamp { .. } => Self::CLAMP,
            PatchOperation::Delay { .. } => Self::DELAY,
        };
        self.0 & bit != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairConstraint {
    pub maximum_edits: u16,
    pub allowed: AllowedOperations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstraintError {
    ZeroEditBudget,
    InvalidOperationMask,
    TooManyEdits,
    ForbiddenOperation,
}

impl RepairConstraint {
    pub fn new(maximum_edits: u16, allowed: AllowedOperations) -> Result<Self, ConstraintError> {
        if maximum_edits == 0 {
            return Err(ConstraintError::ZeroEditBudget);
        }
        Ok(Self {
            maximum_edits,
            allowed,
        })
    }

    pub fn validate(self, repairs: &RepairSet) -> Result<(), ConstraintError> {
        if repairs.edits().len() > usize::from(self.maximum_edits) {
            return Err(ConstraintError::TooManyEdits);
        }
        if repairs
            .edits()
            .iter()
            .any(|edit| !self.allowed.permits(edit.operation))
        {
            return Err(ConstraintError::ForbiddenOperation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_atom::RepairAtom;
    use crate::remedy_set::RepairEdit;

    #[test]
    fn forbidden_operation_fails_closed() {
        let set = RepairSet::new(vec![RepairEdit {
            atom: RepairAtom::new(1, "gate").unwrap(),
            operation: PatchOperation::Delay { slots: 1 },
        }])
        .unwrap();
        let allowed = AllowedOperations::new(AllowedOperations::DISABLE).unwrap();
        assert_eq!(
            RepairConstraint::new(1, allowed).unwrap().validate(&set),
            Err(ConstraintError::ForbiddenOperation)
        );
    }
}
