//! Canonical minimal patch plus the earliest public counterexample trace.

use crate::remedy_set::RepairSet;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepairTraceStep {
    pub slot: u32,
    pub input: u16,
    pub left_state: u32,
    pub right_state: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortestRepairWitness {
    pub patch: RepairSet,
    pub counterexample: Vec<RepairTraceStep>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessError {
    EmptyCounterexample,
    NonMonotonicSlots,
}

impl ShortestRepairWitness {
    pub fn new(
        patch: RepairSet,
        mut counterexample: Vec<RepairTraceStep>,
    ) -> Result<Self, WitnessError> {
        if counterexample.is_empty() {
            return Err(WitnessError::EmptyCounterexample);
        }
        counterexample.sort();
        if counterexample
            .windows(2)
            .any(|pair| pair[0].slot == pair[1].slot)
        {
            return Err(WitnessError::NonMonotonicSlots);
        }
        Ok(Self {
            patch,
            counterexample,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_atom::RepairAtom;
    use crate::remedy_patch_operation::PatchOperation;
    use crate::remedy_set::RepairEdit;

    #[test]
    fn trace_carries_slot_input_and_both_states() {
        let patch = RepairSet::new(vec![RepairEdit {
            atom: RepairAtom::new(2, "gate").unwrap(),
            operation: PatchOperation::Disable,
        }])
        .unwrap();
        let witness = ShortestRepairWitness::new(
            patch,
            vec![RepairTraceStep {
                slot: 3,
                input: 7,
                left_state: 10,
                right_state: 11,
            }],
        )
        .unwrap();
        assert_eq!(
            witness.counterexample[0],
            RepairTraceStep {
                slot: 3,
                input: 7,
                left_state: 10,
                right_state: 11
            }
        );
    }
}
