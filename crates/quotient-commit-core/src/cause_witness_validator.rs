//! Independent validation of complete causal witness conditions.

use crate::{
    cause_contingency::Contingency, cause_equation::StructuralEquation, cause_hp_actuality,
    cause_hp_dependence, cause_hp_minimality, cause_outcome::OutcomePredicate,
    cause_state::CausalState, cause_verdict::CausalInvalidReason,
};

pub fn validate(
    actual: &CausalState,
    witness: &Contingency,
    equations: &[StructuralEquation],
    predicate: OutcomePredicate,
) -> Result<(), CausalInvalidReason> {
    cause_hp_actuality::verify(actual, witness, predicate)?;
    if !cause_hp_dependence::verify(actual, witness, equations, predicate)?
        || !cause_hp_minimality::verify(actual, witness, equations, predicate)?
    {
        return Err(CausalInvalidReason::WitnessRejected);
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

    fn witness(items: Vec<crate::cause_intervention::Intervention>) -> Contingency {
        Contingency::create(
            InterventionSet::canonicalize(items).unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn valid_minimal_witness_passes_all_conditions() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let actual = CausalState::create(1, vec![projection], true).unwrap();
        let change = intervention(projection, InterventionValue::SetPublicBranch(0)).unwrap();
        assert_eq!(
            validate(&actual, &witness(vec![change]), &[], predicate()),
            Ok(())
        );
    }

    #[test]
    fn irrelevant_member_is_rejected() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let irrelevant = atom(1, AtomKind::Transition, 2, 1).unwrap();
        let actual = CausalState::create(1, vec![projection, irrelevant], true).unwrap();
        let changes = vec![
            intervention(projection, InterventionValue::SetPublicBranch(0)).unwrap(),
            intervention(irrelevant, InterventionValue::SetPublicBranch(0)).unwrap(),
        ];
        assert_eq!(
            validate(&actual, &witness(changes), &[], predicate()),
            Err(CausalInvalidReason::WitnessRejected)
        );
    }
}
