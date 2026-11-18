//! Halpern-Pearl counterfactual dependence condition.

use crate::{
    cause_contingency::Contingency, cause_counterfactual_world::generate,
    cause_equation::StructuralEquation, cause_hp_actuality, cause_outcome::OutcomePredicate,
    cause_state::CausalState, cause_verdict::CausalInvalidReason,
};

pub fn verify(
    actual: &CausalState,
    witness: &Contingency,
    equations: &[StructuralEquation],
    predicate: OutcomePredicate,
) -> Result<bool, CausalInvalidReason> {
    cause_hp_actuality::verify(actual, witness, predicate)?;
    let combined = witness.combined()?;
    let counterfactual = generate(actual, &combined, equations)?;
    Ok(!predicate.evaluate(&counterfactual)?)
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

    fn witness(atom: crate::cause_atom::CausalAtom) -> Contingency {
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
    fn outcome_flip_establishes_dependence() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let actual = CausalState::create(1, vec![projection], true).unwrap();
        assert_eq!(
            verify(&actual, &witness(projection), &[], predicate()),
            Ok(true)
        );
    }

    #[test]
    fn irrelevant_intervention_is_not_dependence() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let transition = atom(1, AtomKind::Transition, 2, 1).unwrap();
        let actual = CausalState::create(1, vec![projection, transition], true).unwrap();
        assert_eq!(
            verify(&actual, &witness(transition), &[], predicate()),
            Ok(false)
        );
    }

    #[test]
    fn false_actual_outcome_is_invalid() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let actual = CausalState::create(1, vec![projection], false).unwrap();
        assert_eq!(
            verify(&actual, &witness(projection), &[], predicate()),
            Err(CausalInvalidReason::ActualWorldMismatch)
        );
    }
}
