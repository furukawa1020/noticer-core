//! Halpern-Pearl actuality condition for a proposed cause witness.

use crate::{
    cause_contingency::Contingency, cause_outcome::OutcomePredicate, cause_state::CausalState,
    cause_verdict::CausalInvalidReason,
};

pub fn verify(
    actual: &CausalState,
    witness: &Contingency,
    predicate: OutcomePredicate,
) -> Result<(), CausalInvalidReason> {
    if !predicate.evaluate(actual)? {
        return Err(CausalInvalidReason::ActualWorldMismatch);
    }
    if witness
        .cause()
        .as_slice()
        .iter()
        .any(|intervention| !actual.atoms().contains(&intervention.atom))
    {
        return Err(CausalInvalidReason::ActualWorldMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
        cause_intervention_set::InterventionSet,
        cause_outcome::OutcomeKind,
    };

    fn predicate() -> OutcomePredicate {
        OutcomePredicate {
            kind: OutcomeKind::ObserverDivergence,
            expected: true,
        }
    }

    fn witness(actual_branch: u16) -> Contingency {
        let projection = atom(1, AtomKind::ObserverProjection, 1, actual_branch).unwrap();
        Contingency::create(
            InterventionSet::canonicalize(vec![intervention(
                projection,
                InterventionValue::SetPublicBranch(0),
            )
            .unwrap()])
            .unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn matching_actual_cause_is_accepted() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let actual = CausalState::create(1, vec![projection], true).unwrap();
        assert_eq!(verify(&actual, &witness(1), predicate()), Ok(()));
    }

    #[test]
    fn substituted_actual_branch_is_rejected() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let actual = CausalState::create(1, vec![projection], true).unwrap();
        assert_eq!(
            verify(&actual, &witness(2), predicate()),
            Err(CausalInvalidReason::ActualWorldMismatch)
        );
    }

    #[test]
    fn absent_actual_outcome_is_rejected() {
        let actual = CausalState::create(1, vec![], false).unwrap();
        assert_eq!(
            verify(&actual, &witness(1), predicate()),
            Err(CausalInvalidReason::ActualWorldMismatch)
        );
    }
}
