//! Public redaction of causal witnesses for explanatory surfaces.

use crate::{cause_atom::AtomKind, cause_contingency::Contingency};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RedactedCause {
    pub slot: u64,
    pub kind_code: u8,
    pub field_id: u16,
}

pub fn redact(witness: &Contingency) -> Vec<RedactedCause> {
    let mut causes: Vec<_> = witness
        .cause()
        .as_slice()
        .iter()
        .map(|intervention| RedactedCause {
            slot: intervention.atom.slot,
            kind_code: kind_code(intervention.atom.kind),
            field_id: intervention.atom.field_id,
        })
        .collect();
    causes.sort_unstable();
    causes.dedup();
    causes
}

fn kind_code(kind: AtomKind) -> u8 {
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
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
        cause_intervention_set::InterventionSet,
    };

    fn witness(branch: u16) -> Contingency {
        let atom = atom(4, AtomKind::AuthorizedRelease, 7, branch).unwrap();
        Contingency::create(
            InterventionSet::canonicalize(vec![intervention(
                atom,
                InterventionValue::SetPublicBranch(branch + 1),
            )
            .unwrap()])
            .unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn explanation_contains_only_structural_coordinates() {
        assert_eq!(
            redact(&witness(3)),
            vec![RedactedCause {
                slot: 4,
                kind_code: 2,
                field_id: 7
            }]
        );
    }

    #[test]
    fn actual_branch_does_not_change_public_explanation() {
        assert_eq!(redact(&witness(3)), redact(&witness(9)));
    }
}
