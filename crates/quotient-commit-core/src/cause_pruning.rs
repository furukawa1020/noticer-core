//! Sound pruning of atoms outside a previously extracted causal cone.

use crate::{
    cause_atom::{AtomKind, CausalAtom},
    cause_state::CausalState,
    cause_verdict::CausalInvalidReason,
};

pub fn prune(state: &CausalState, cone: &[CausalAtom]) -> Result<CausalState, CausalInvalidReason> {
    if cone.iter().any(|atom| !state.atoms().contains(atom)) {
        return Err(CausalInvalidReason::Domain);
    }
    let atoms: Vec<_> = state
        .atoms()
        .iter()
        .filter(|atom| cone.contains(atom))
        .copied()
        .collect();
    let outcome = atoms
        .iter()
        .any(|atom| atom.kind == AtomKind::ObserverProjection && atom.public_branch != 0);
    CausalState::create(state.slot, atoms, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_atom::{create as atom, AtomKind};

    #[test]
    fn irrelevant_atom_is_removed() {
        let relevant = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let irrelevant = atom(1, AtomKind::Transition, 2, 1).unwrap();
        let state = CausalState::create(1, vec![relevant, irrelevant], true).unwrap();
        let pruned = prune(&state, &[relevant]).unwrap();
        assert_eq!(pruned.atoms(), &[relevant]);
        assert!(pruned.outcome);
    }

    #[test]
    fn unknown_cone_atom_is_invalid() {
        let state = CausalState::create(1, vec![], false).unwrap();
        let unknown = atom(1, AtomKind::Transition, 1, 0).unwrap();
        assert_eq!(prune(&state, &[unknown]), Err(CausalInvalidReason::Domain));
    }

    #[test]
    fn removing_projection_recomputes_outcome() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let state = CausalState::create(1, vec![projection], true).unwrap();
        assert!(!prune(&state, &[]).unwrap().outcome);
    }
}
