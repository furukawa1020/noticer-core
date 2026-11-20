//! Canonical sets of non-conflicting repair edits.

use crate::remedy_atom::RepairAtom;
use crate::remedy_patch_operation::{PatchOperation, PatchOperationError};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepairEdit {
    pub atom: RepairAtom,
    pub operation: PatchOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairSet(Vec<RepairEdit>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairSetError {
    Empty,
    InvalidOperation(PatchOperationError),
    ConflictingTarget,
}

impl RepairSet {
    pub fn new(mut edits: Vec<RepairEdit>) -> Result<Self, RepairSetError> {
        if edits.is_empty() {
            return Err(RepairSetError::Empty);
        }
        for edit in &edits {
            edit.operation
                .validate()
                .map_err(RepairSetError::InvalidOperation)?;
        }
        edits.sort();
        edits.dedup();
        if edits.windows(2).any(|pair| pair[0].atom == pair[1].atom) {
            return Err(RepairSetError::ConflictingTarget);
        }
        Ok(Self(edits))
    }

    #[must_use]
    pub fn edits(&self) -> &[RepairEdit] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(slot: u32, op: PatchOperation) -> RepairEdit {
        RepairEdit {
            atom: RepairAtom::new(slot, "gate").unwrap(),
            operation: op,
        }
    }

    #[test]
    fn order_and_duplicates_are_canonicalized() {
        let a = edit(1, PatchOperation::Disable);
        let b = edit(2, PatchOperation::Delay { slots: 1 });
        let set = RepairSet::new(vec![b.clone(), a.clone(), a]).unwrap();
        assert_eq!(set.edits(), &[edit(1, PatchOperation::Disable), b]);
    }

    #[test]
    fn conflicting_edits_are_rejected() {
        assert_eq!(
            RepairSet::new(vec![
                edit(1, PatchOperation::Disable),
                edit(1, PatchOperation::Substitute { public_code: 2 }),
            ]),
            Err(RepairSetError::ConflictingTarget)
        );
    }
}
