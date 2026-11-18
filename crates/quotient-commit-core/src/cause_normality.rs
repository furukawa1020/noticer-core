//! Explicit normality ranking for counterfactual interventions.

use crate::{
    cause_atom::CausalAtom, cause_intervention_set::InterventionSet,
    cause_verdict::CausalInvalidReason,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalityProfile(Vec<(CausalAtom, u32)>);

impl NormalityProfile {
    pub fn create(mut entries: Vec<(CausalAtom, u32)>) -> Result<Self, CausalInvalidReason> {
        entries.sort_unstable_by_key(|entry| entry.0);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(CausalInvalidReason::NonCanonical);
        }
        Ok(Self(entries))
    }

    pub fn rank(&self, interventions: &InterventionSet) -> Result<u64, CausalInvalidReason> {
        interventions
            .as_slice()
            .iter()
            .try_fold(0_u64, |rank, intervention| {
                let penalty = self
                    .0
                    .iter()
                    .find(|entry| entry.0 == intervention.atom)
                    .map(|entry| entry.1)
                    .ok_or(CausalInvalidReason::Domain)?;
                Ok(rank.saturating_add(u64::from(penalty)))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
    };

    fn atom_and_intervention(field: u16) -> (CausalAtom, crate::cause_intervention::Intervention) {
        let value = atom(1, AtomKind::Transition, field, 0).unwrap();
        let change = intervention(value, InterventionValue::SetPublicBranch(1)).unwrap();
        (value, change)
    }

    #[test]
    fn penalties_sum_deterministically() {
        let (a, change_a) = atom_and_intervention(1);
        let (b, change_b) = atom_and_intervention(2);
        let profile = NormalityProfile::create(vec![(b, 5), (a, 2)]).unwrap();
        let set = InterventionSet::canonicalize(vec![change_b, change_a]).unwrap();
        assert_eq!(profile.rank(&set), Ok(7));
    }

    #[test]
    fn unknown_atom_is_invalid() {
        let (_, change) = atom_and_intervention(1);
        let profile = NormalityProfile::create(vec![]).unwrap();
        let set = InterventionSet::canonicalize(vec![change]).unwrap();
        assert_eq!(profile.rank(&set), Err(CausalInvalidReason::Domain));
    }
}
