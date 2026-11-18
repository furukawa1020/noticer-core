//! Public-safe atom identifiers used by counterfactual causality models.

use crate::cause_verdict::CausalInvalidReason;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AtomKind {
    PublicInput,
    Transition,
    AuthorizedRelease,
    ObserverProjection,
    PermitDecision,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CausalAtom {
    pub slot: u64,
    pub kind: AtomKind,
    pub field_id: u16,
    pub public_branch: u16,
}

pub fn create(
    slot: u64,
    kind: AtomKind,
    field_id: u16,
    public_branch: u16,
) -> Result<CausalAtom, CausalInvalidReason> {
    if field_id == 0 {
        return Err(CausalInvalidReason::Domain);
    }
    Ok(CausalAtom {
        slot,
        kind,
        field_id,
        public_branch,
    })
}

pub fn canonical_bytes(atom: CausalAtom) -> [u8; 13] {
    let mut out = [0_u8; 13];
    out[..8].copy_from_slice(&atom.slot.to_be_bytes());
    out[8] = match atom.kind {
        AtomKind::PublicInput => 0,
        AtomKind::Transition => 1,
        AtomKind::AuthorizedRelease => 2,
        AtomKind::ObserverProjection => 3,
        AtomKind::PermitDecision => 4,
    };
    out[9..11].copy_from_slice(&atom.field_id.to_be_bytes());
    out[11..13].copy_from_slice(&atom.public_branch.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atom_contains_only_public_structural_coordinates() {
        let atom = create(7, AtomKind::AuthorizedRelease, 3, 1).unwrap();
        assert_eq!(atom.slot, 7);
        assert_eq!(canonical_bytes(atom).len(), 13);
    }

    #[test]
    fn zero_field_identifier_is_invalid() {
        assert_eq!(
            create(0, AtomKind::PublicInput, 0, 9),
            Err(CausalInvalidReason::Domain)
        );
    }

    #[test]
    fn ordering_is_deterministic() {
        let earlier = create(1, AtomKind::Transition, 1, 0).unwrap();
        let later = create(2, AtomKind::Transition, 1, 0).unwrap();
        assert!(earlier < later);
    }
}
