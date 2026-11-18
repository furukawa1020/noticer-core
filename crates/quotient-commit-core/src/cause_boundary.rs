//! Explicit trust and resource boundary for a bounded causal model.

use crate::{cause_atom::AtomKind, cause_state::CausalState, cause_verdict::CausalInvalidReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelBoundary {
    pub first_slot: u64,
    pub last_slot: u64,
    pub maximum_atoms: usize,
    allowed_kinds: [bool; 5],
}

impl ModelBoundary {
    pub fn create(
        first_slot: u64,
        last_slot: u64,
        maximum_atoms: usize,
        allowed: &[AtomKind],
    ) -> Result<Self, CausalInvalidReason> {
        if last_slot < first_slot || maximum_atoms == 0 {
            return Err(CausalInvalidReason::Domain);
        }
        let mut allowed_kinds = [false; 5];
        for kind in allowed {
            allowed_kinds[kind_index(*kind)] = true;
        }
        Ok(Self {
            first_slot,
            last_slot,
            maximum_atoms,
            allowed_kinds,
        })
    }

    pub fn validate(self, state: &CausalState) -> Result<(), CausalInvalidReason> {
        if state.atoms().len() > self.maximum_atoms
            || state.slot < self.first_slot
            || state.slot > self.last_slot.saturating_add(1)
            || state.atoms().iter().any(|atom| {
                atom.slot < self.first_slot
                    || atom.slot > self.last_slot
                    || !self.allowed_kinds[kind_index(atom.kind)]
            })
        {
            return Err(CausalInvalidReason::Domain);
        }
        Ok(())
    }
}

fn kind_index(kind: AtomKind) -> usize {
    match kind {
        AtomKind::PublicInput => 0,
        AtomKind::Transition => 1,
        AtomKind::AuthorizedRelease => 2,
        AtomKind::ObserverProjection => 3,
        AtomKind::PermitDecision => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_atom::create as atom;

    #[test]
    fn in_boundary_state_is_accepted() {
        let boundary = ModelBoundary::create(1, 3, 2, &[AtomKind::Transition]).unwrap();
        let state =
            CausalState::create(2, vec![atom(2, AtomKind::Transition, 1, 0).unwrap()], false)
                .unwrap();
        assert_eq!(boundary.validate(&state), Ok(()));
    }

    #[test]
    fn disallowed_namespace_is_rejected() {
        let boundary = ModelBoundary::create(1, 3, 2, &[AtomKind::Transition]).unwrap();
        let state = CausalState::create(
            2,
            vec![atom(2, AtomKind::PermitDecision, 1, 0).unwrap()],
            false,
        )
        .unwrap();
        assert_eq!(boundary.validate(&state), Err(CausalInvalidReason::Domain));
    }

    #[test]
    fn zero_capacity_boundary_is_invalid() {
        assert_eq!(
            ModelBoundary::create(1, 1, 0, &[]),
            Err(CausalInvalidReason::Domain)
        );
    }
}
