//! Deterministic repair candidates derived from public cause locations.

use crate::remedy_atom::RepairAtom;
use crate::remedy_patch_operation::PatchOperation;
use crate::remedy_set::{RepairEdit, RepairSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairCandidateGenerator {
    include_delay: bool,
}

impl RepairCandidateGenerator {
    #[must_use]
    pub const fn new(include_delay: bool) -> Self {
        Self { include_delay }
    }

    pub fn generate(&self, atoms: &[RepairAtom]) -> Vec<RepairSet> {
        let mut atoms = atoms.to_vec();
        atoms.sort();
        atoms.dedup();
        let mut candidates = Vec::new();
        for atom in atoms {
            candidates.push(
                RepairSet::new(vec![RepairEdit {
                    atom: atom.clone(),
                    operation: PatchOperation::Disable,
                }])
                .expect("one valid deterministic edit"),
            );
            if self.include_delay {
                candidates.push(
                    RepairSet::new(vec![RepairEdit {
                        atom,
                        operation: PatchOperation::Delay { slots: 1 },
                    }])
                    .expect("one valid deterministic edit"),
                );
            }
        }
        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_order_and_duplicates_do_not_change_candidates() {
        let a = RepairAtom::new(1, "a").unwrap();
        let b = RepairAtom::new(2, "b").unwrap();
        let generator = RepairCandidateGenerator::new(true);
        assert_eq!(
            generator.generate(&[b.clone(), a.clone(), a.clone()]),
            generator.generate(&[a, b])
        );
    }
}
