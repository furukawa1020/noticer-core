//! Disjoint cause and contingency intervention sets.

use crate::{
    cause_intervention::Intervention, cause_intervention_set::InterventionSet,
    cause_verdict::CausalInvalidReason,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contingency {
    cause: InterventionSet,
    context: InterventionSet,
}

impl Contingency {
    pub fn create(
        cause: InterventionSet,
        context: InterventionSet,
    ) -> Result<Self, CausalInvalidReason> {
        if cause.as_slice().is_empty() {
            return Err(CausalInvalidReason::Domain);
        }
        if cause.as_slice().iter().any(|left| {
            context
                .as_slice()
                .iter()
                .any(|right| left.atom == right.atom)
        }) {
            return Err(CausalInvalidReason::Domain);
        }
        Ok(Self { cause, context })
    }

    pub fn cause(&self) -> &InterventionSet {
        &self.cause
    }

    pub fn context(&self) -> &InterventionSet {
        &self.context
    }

    pub fn combined(&self) -> Result<InterventionSet, CausalInvalidReason> {
        let interventions: Vec<Intervention> = self
            .cause
            .as_slice()
            .iter()
            .chain(self.context.as_slice())
            .copied()
            .collect();
        InterventionSet::canonicalize(interventions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
    };

    fn item(field: u16, branch: u16) -> Intervention {
        intervention(
            atom(1, AtomKind::Transition, field, 0).unwrap(),
            InterventionValue::SetPublicBranch(branch),
        )
        .unwrap()
    }

    #[test]
    fn disjoint_sets_combine_canonically() {
        let witness = Contingency::create(
            InterventionSet::canonicalize(vec![item(2, 1)]).unwrap(),
            InterventionSet::canonicalize(vec![item(1, 1)]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            witness.combined().unwrap().as_slice(),
            &[item(1, 1), item(2, 1)]
        );
    }

    #[test]
    fn overlap_is_invalid() {
        let set = InterventionSet::canonicalize(vec![item(1, 1)]).unwrap();
        assert_eq!(
            Contingency::create(set.clone(), set),
            Err(CausalInvalidReason::Domain)
        );
    }

    #[test]
    fn empty_cause_is_invalid() {
        let empty = InterventionSet::canonicalize(vec![]).unwrap();
        assert_eq!(
            Contingency::create(empty.clone(), empty),
            Err(CausalInvalidReason::Domain)
        );
    }
}
