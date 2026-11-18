//! Canonical public-safe snapshot of a bounded causal world.

use crate::{
    cause_atom::{canonical_bytes, CausalAtom},
    cause_verdict::CausalInvalidReason,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalState {
    pub slot: u64,
    atoms: Vec<CausalAtom>,
    pub outcome: bool,
}

impl CausalState {
    pub fn create(
        slot: u64,
        mut atoms: Vec<CausalAtom>,
        outcome: bool,
    ) -> Result<Self, CausalInvalidReason> {
        if atoms.iter().any(|atom| atom.slot > slot) {
            return Err(CausalInvalidReason::Domain);
        }
        atoms.sort_unstable();
        if atoms.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CausalInvalidReason::NonCanonical);
        }
        Ok(Self {
            slot,
            atoms,
            outcome,
        })
    }

    pub fn atoms(&self) -> &[CausalAtom] {
        &self.atoms
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.slot.to_be_bytes().to_vec();
        out.push(u8::from(self.outcome));
        out.extend_from_slice(&(self.atoms.len() as u64).to_be_bytes());
        for atom in &self.atoms {
            out.extend_from_slice(&canonical_bytes(*atom));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_atom::{create as atom, AtomKind};

    fn at(slot: u64, field: u16) -> CausalAtom {
        atom(slot, AtomKind::Transition, field, 0).unwrap()
    }

    #[test]
    fn atoms_are_stored_in_canonical_order() {
        let state = CausalState::create(2, vec![at(2, 2), at(1, 1)], true).unwrap();
        assert_eq!(state.atoms(), &[at(1, 1), at(2, 2)]);
        assert!(!state.canonical_bytes().is_empty());
    }

    #[test]
    fn future_atom_is_invalid() {
        assert_eq!(
            CausalState::create(1, vec![at(2, 1)], false),
            Err(CausalInvalidReason::Domain)
        );
    }

    #[test]
    fn duplicate_atom_is_noncanonical() {
        assert_eq!(
            CausalState::create(1, vec![at(1, 1), at(1, 1)], false),
            Err(CausalInvalidReason::NonCanonical)
        );
    }
}
