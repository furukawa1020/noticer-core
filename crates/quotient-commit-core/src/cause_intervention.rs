//! Typed, public-safe interventions over causal atoms.

use crate::{
    cause_atom::{canonical_bytes, CausalAtom},
    cause_verdict::CausalInvalidReason,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InterventionValue {
    Remove,
    SetPublicBranch(u16),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Intervention {
    pub atom: CausalAtom,
    pub replacement: InterventionValue,
}

pub fn create(
    atom: CausalAtom,
    replacement: InterventionValue,
) -> Result<Intervention, CausalInvalidReason> {
    if matches!(replacement, InterventionValue::SetPublicBranch(value) if value == atom.public_branch)
    {
        return Err(CausalInvalidReason::NonCanonical);
    }
    Ok(Intervention { atom, replacement })
}

pub fn encode(intervention: Intervention) -> Vec<u8> {
    let mut out = canonical_bytes(intervention.atom).to_vec();
    match intervention.replacement {
        InterventionValue::Remove => out.push(0),
        InterventionValue::SetPublicBranch(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_atom::{create as atom, AtomKind};

    fn release() -> CausalAtom {
        atom(3, AtomKind::AuthorizedRelease, 2, 7).unwrap()
    }

    #[test]
    fn public_branch_replacement_is_canonical() {
        let value = create(release(), InterventionValue::SetPublicBranch(8)).unwrap();
        assert_eq!(value.replacement, InterventionValue::SetPublicBranch(8));
        assert!(!encode(value).is_empty());
    }

    #[test]
    fn no_op_intervention_is_rejected() {
        assert_eq!(
            create(release(), InterventionValue::SetPublicBranch(7)),
            Err(CausalInvalidReason::NonCanonical)
        );
    }

    #[test]
    fn removal_is_distinct_from_branch_zero() {
        assert_ne!(
            create(release(), InterventionValue::Remove).unwrap(),
            create(release(), InterventionValue::SetPublicBranch(0)).unwrap()
        );
    }
}
