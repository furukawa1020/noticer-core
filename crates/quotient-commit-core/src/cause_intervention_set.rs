//! Canonical sets of non-conflicting counterfactual interventions.

use crate::{
    cause_intervention::{encode, Intervention},
    cause_verdict::CausalInvalidReason,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterventionSet(Vec<Intervention>);

impl InterventionSet {
    pub fn canonicalize(mut interventions: Vec<Intervention>) -> Result<Self, CausalInvalidReason> {
        interventions.sort_unstable();
        let mut canonical: Vec<Intervention> = Vec::with_capacity(interventions.len());
        for intervention in interventions {
            if let Some(previous) = canonical.last() {
                if previous == &intervention {
                    continue;
                }
                if previous.atom == intervention.atom {
                    return Err(CausalInvalidReason::Domain);
                }
            }
            canonical.push(intervention);
        }
        Ok(Self(canonical))
    }

    pub fn as_slice(&self) -> &[Intervention] {
        &self.0
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = (self.0.len() as u64).to_be_bytes().to_vec();
        for intervention in &self.0 {
            let bytes = encode(*intervention);
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create, InterventionValue},
    };

    fn intervention(field: u16, branch: u16) -> Intervention {
        create(
            atom(1, AtomKind::Transition, field, 0).unwrap(),
            InterventionValue::SetPublicBranch(branch),
        )
        .unwrap()
    }

    #[test]
    fn ordering_and_deduplication_are_deterministic() {
        let set = InterventionSet::canonicalize(vec![
            intervention(2, 1),
            intervention(1, 1),
            intervention(1, 1),
        ])
        .unwrap();
        assert_eq!(set.as_slice(), &[intervention(1, 1), intervention(2, 1)]);
    }

    #[test]
    fn conflicting_replacements_are_invalid() {
        assert_eq!(
            InterventionSet::canonicalize(vec![intervention(1, 1), intervention(1, 2)]),
            Err(CausalInvalidReason::Domain)
        );
    }

    #[test]
    fn empty_contingency_has_canonical_encoding() {
        let set = InterventionSet::canonicalize(vec![]).unwrap();
        assert_eq!(set.canonical_bytes(), 0_u64.to_be_bytes());
    }
}
