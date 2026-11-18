//! Temporal precedence constraints for proposed causes.

use crate::{cause_contingency::Contingency, cause_verdict::CausalInvalidReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalConstraint {
    pub outcome_slot: u64,
    pub maximum_lag: u64,
}

impl TemporalConstraint {
    pub fn validate(self, witness: &Contingency) -> Result<(), CausalInvalidReason> {
        if witness.cause().as_slice().iter().any(|intervention| {
            intervention.atom.slot > self.outcome_slot
                || self.outcome_slot - intervention.atom.slot > self.maximum_lag
        }) {
            return Err(CausalInvalidReason::Domain);
        }
        Ok(())
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

    fn witness(slot: u64) -> Contingency {
        let atom = atom(slot, AtomKind::Transition, 1, 1).unwrap();
        Contingency::create(
            InterventionSet::canonicalize(vec![intervention(
                atom,
                InterventionValue::SetPublicBranch(0),
            )
            .unwrap()])
            .unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn bounded_predecessor_is_valid() {
        let constraint = TemporalConstraint {
            outcome_slot: 10,
            maximum_lag: 3,
        };
        assert_eq!(constraint.validate(&witness(7)), Ok(()));
    }

    #[test]
    fn future_and_stale_causes_are_rejected() {
        let constraint = TemporalConstraint {
            outcome_slot: 10,
            maximum_lag: 3,
        };
        assert_eq!(
            constraint.validate(&witness(11)),
            Err(CausalInvalidReason::Domain)
        );
        assert_eq!(
            constraint.validate(&witness(6)),
            Err(CausalInvalidReason::Domain)
        );
    }
}
