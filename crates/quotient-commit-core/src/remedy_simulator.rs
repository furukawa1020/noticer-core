//! Pure counterfactual application of a normalized repair set.

use std::collections::BTreeMap;

use crate::remedy_patch_operation::PatchOperation;
use crate::remedy_set::RepairSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicWorld {
    pub values: BTreeMap<(u32, String), i32>,
    pub disabled: Vec<(u32, String)>,
    pub accumulated_delay: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationError {
    MissingTarget,
    DelayOverflow,
}

pub fn simulate(actual: &PublicWorld, repairs: &RepairSet) -> Result<PublicWorld, SimulationError> {
    let mut world = actual.clone();
    for edit in repairs.edits() {
        let key = (edit.atom.slot(), edit.atom.target().to_owned());
        match edit.operation {
            PatchOperation::Disable => {
                if !world.values.contains_key(&key) {
                    return Err(SimulationError::MissingTarget);
                }
                world.disabled.push(key);
            }
            PatchOperation::Substitute { public_code } => {
                *world
                    .values
                    .get_mut(&key)
                    .ok_or(SimulationError::MissingTarget)? = i32::from(public_code);
            }
            PatchOperation::Clamp { minimum, maximum } => {
                let value = world
                    .values
                    .get_mut(&key)
                    .ok_or(SimulationError::MissingTarget)?;
                *value = (*value).clamp(minimum, maximum);
            }
            PatchOperation::Delay { slots } => {
                if !world.values.contains_key(&key) {
                    return Err(SimulationError::MissingTarget);
                }
                world.accumulated_delay = world
                    .accumulated_delay
                    .checked_add(u32::from(slots))
                    .ok_or(SimulationError::DelayOverflow)?;
            }
        }
    }
    world.disabled.sort();
    world.disabled.dedup();
    Ok(world)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_atom::RepairAtom;
    use crate::remedy_set::RepairEdit;

    #[test]
    fn simulation_does_not_mutate_actual_world() {
        let key = (1, "gate".to_owned());
        let actual = PublicWorld {
            values: BTreeMap::from([(key.clone(), 9)]),
            disabled: vec![],
            accumulated_delay: 0,
        };
        let set = RepairSet::new(vec![RepairEdit {
            atom: RepairAtom::new(1, "gate").unwrap(),
            operation: PatchOperation::Clamp {
                minimum: 0,
                maximum: 3,
            },
        }])
        .unwrap();
        let changed = simulate(&actual, &set).unwrap();
        assert_eq!(actual.values[&key], 9);
        assert_eq!(changed.values[&key], 3);
    }
}
