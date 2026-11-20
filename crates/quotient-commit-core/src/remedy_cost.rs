//! Deterministic integer costs for normalized repairs.

use crate::remedy_patch_operation::PatchOperation;
use crate::remedy_set::RepairSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairCost {
    pub edits: u32,
    pub delay_slots: u32,
    pub semantic_distance: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CostError {
    CountOverflow,
    DelayOverflow,
}

pub fn measure(repairs: &RepairSet) -> Result<RepairCost, CostError> {
    let edits = u32::try_from(repairs.edits().len()).map_err(|_| CostError::CountOverflow)?;
    let mut delay_slots = 0_u32;
    let mut semantic_distance = 0_u32;
    for edit in repairs.edits() {
        match edit.operation {
            PatchOperation::Disable => semantic_distance += 4,
            PatchOperation::Substitute { .. } => semantic_distance += 2,
            PatchOperation::Clamp { .. } => semantic_distance += 1,
            PatchOperation::Delay { slots } => {
                delay_slots = delay_slots
                    .checked_add(u32::from(slots))
                    .ok_or(CostError::DelayOverflow)?;
            }
        }
    }
    Ok(RepairCost {
        edits,
        delay_slots,
        semantic_distance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_atom::RepairAtom;
    use crate::remedy_set::RepairEdit;

    #[test]
    fn operation_costs_are_integer_and_stable() {
        let set = RepairSet::new(vec![
            RepairEdit {
                atom: RepairAtom::new(1, "a").unwrap(),
                operation: PatchOperation::Disable,
            },
            RepairEdit {
                atom: RepairAtom::new(2, "b").unwrap(),
                operation: PatchOperation::Delay { slots: 3 },
            },
        ])
        .unwrap();
        assert_eq!(
            measure(&set),
            Ok(RepairCost {
                edits: 2,
                delay_slots: 3,
                semantic_distance: 4
            })
        );
    }
}
