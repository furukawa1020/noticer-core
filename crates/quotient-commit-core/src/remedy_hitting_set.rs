//! Deterministic greedy cover for multiple certified cause sets.

use std::collections::{BTreeMap, BTreeSet};

use crate::remedy_atom::RepairAtom;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HittingSetError {
    EmptyFamily,
    EmptyCauseSet,
}

pub fn deterministic_hitting_set(
    family: &[BTreeSet<RepairAtom>],
) -> Result<Vec<RepairAtom>, HittingSetError> {
    if family.is_empty() {
        return Err(HittingSetError::EmptyFamily);
    }
    if family.iter().any(BTreeSet::is_empty) {
        return Err(HittingSetError::EmptyCauseSet);
    }
    let mut remaining: BTreeSet<usize> = (0..family.len()).collect();
    let mut result = Vec::new();
    while !remaining.is_empty() {
        let mut counts = BTreeMap::<RepairAtom, usize>::new();
        for index in &remaining {
            for atom in &family[*index] {
                *counts.entry(atom.clone()).or_default() += 1;
            }
        }
        let atom = counts
            .into_iter()
            .max_by(|(left_atom, left_count), (right_atom, right_count)| {
                left_count
                    .cmp(right_count)
                    .then_with(|| right_atom.cmp(left_atom))
            })
            .expect("non-empty causes")
            .0;
        remaining.retain(|index| !family[*index].contains(&atom));
        result.push(atom);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_atom_is_selected_first() {
        let a = RepairAtom::new(1, "a").unwrap();
        let b = RepairAtom::new(2, "b").unwrap();
        let c = RepairAtom::new(3, "c").unwrap();
        let result = deterministic_hitting_set(&[
            BTreeSet::from([a.clone(), b]),
            BTreeSet::from([a.clone(), c]),
        ])
        .unwrap();
        assert_eq!(result, vec![a]);
    }
}
