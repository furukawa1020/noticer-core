//! Policy gate for admissible counterfactual interventions.

use crate::{
    cause_atom::AtomKind, cause_intervention::InterventionValue,
    cause_intervention_set::InterventionSet, cause_verdict::CausalInvalidReason,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterventionPolicy {
    pub maximum_interventions: usize,
    pub allow_removal: bool,
    allowed_kinds: [bool; 5],
}

impl InterventionPolicy {
    pub fn create(
        maximum_interventions: usize,
        allow_removal: bool,
        allowed: &[AtomKind],
    ) -> Result<Self, CausalInvalidReason> {
        if maximum_interventions == 0 {
            return Err(CausalInvalidReason::Domain);
        }
        let mut allowed_kinds = [false; 5];
        for kind in allowed {
            allowed_kinds[index(*kind)] = true;
        }
        Ok(Self {
            maximum_interventions,
            allow_removal,
            allowed_kinds,
        })
    }

    pub fn validate(self, set: &InterventionSet) -> Result<(), CausalInvalidReason> {
        if set.as_slice().len() > self.maximum_interventions
            || set.as_slice().iter().any(|intervention| {
                !self.allowed_kinds[index(intervention.atom.kind)]
                    || (!self.allow_removal
                        && intervention.replacement == InterventionValue::Remove)
            })
        {
            return Err(CausalInvalidReason::Domain);
        }
        Ok(())
    }
}

fn index(kind: AtomKind) -> usize {
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
    use crate::{cause_atom::create as atom, cause_intervention::create as intervention};

    fn set(kind: AtomKind, replacement: InterventionValue) -> InterventionSet {
        let value = atom(1, kind, 1, 1).unwrap();
        InterventionSet::canonicalize(vec![intervention(value, replacement).unwrap()]).unwrap()
    }

    #[test]
    fn allowlisted_branch_change_passes() {
        let policy = InterventionPolicy::create(1, false, &[AtomKind::Transition]).unwrap();
        assert_eq!(
            policy.validate(&set(
                AtomKind::Transition,
                InterventionValue::SetPublicBranch(0)
            )),
            Ok(())
        );
    }

    #[test]
    fn removal_and_unknown_namespace_fail_closed() {
        let policy = InterventionPolicy::create(1, false, &[AtomKind::Transition]).unwrap();
        assert_eq!(
            policy.validate(&set(AtomKind::Transition, InterventionValue::Remove)),
            Err(CausalInvalidReason::Domain)
        );
        assert_eq!(
            policy.validate(&set(
                AtomKind::PermitDecision,
                InterventionValue::SetPublicBranch(0)
            )),
            Err(CausalInvalidReason::Domain)
        );
    }
}
