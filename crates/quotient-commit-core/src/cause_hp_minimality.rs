//! One-minimality verification for HP actual causes.

use crate::{
    cause_contingency::Contingency, cause_equation::StructuralEquation, cause_hp_dependence,
    cause_intervention_set::InterventionSet, cause_outcome::OutcomePredicate,
    cause_state::CausalState, cause_verdict::CausalInvalidReason,
};

pub fn verify(
    actual: &CausalState,
    witness: &Contingency,
    equations: &[StructuralEquation],
    predicate: OutcomePredicate,
) -> Result<bool, CausalInvalidReason> {
    if !cause_hp_dependence::verify(actual, witness, equations, predicate)? {
        return Ok(false);
    }
    let cause = witness.cause().as_slice();
    if cause.len() == 1 {
        return Ok(true);
    }
    for removed in 0..cause.len() {
        let reduced = cause
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != removed)
            .map(|(_, intervention)| *intervention)
            .collect();
        let reduced = Contingency::create(
            InterventionSet::canonicalize(reduced)?,
            witness.context().clone(),
        )?;
        if cause_hp_dependence::verify(actual, &reduced, equations, predicate)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
        cause_outcome::OutcomeKind,
    };

    fn intervention_for(
        atom: crate::cause_atom::CausalAtom,
    ) -> crate::cause_intervention::Intervention {
        intervention(atom, InterventionValue::SetPublicBranch(0)).unwrap()
    }

    fn predicate() -> OutcomePredicate {
        OutcomePredicate {
            kind: OutcomeKind::ObserverDivergence,
            expected: true,
        }
    }

    #[test]
    fn jointly_necessary_pair_is_minimal() {
        let a = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let b = atom(1, AtomKind::ObserverProjection, 2, 1).unwrap();
        let actual = CausalState::create(1, vec![a, b], true).unwrap();
        let witness = Contingency::create(
            InterventionSet::canonicalize(vec![intervention_for(a), intervention_for(b)]).unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(verify(&actual, &witness, &[], predicate()), Ok(true));
    }

    #[test]
    fn irrelevant_member_breaks_minimality() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let irrelevant = atom(1, AtomKind::Transition, 2, 1).unwrap();
        let actual = CausalState::create(1, vec![projection, irrelevant], true).unwrap();
        let witness = Contingency::create(
            InterventionSet::canonicalize(vec![
                intervention_for(projection),
                intervention_for(irrelevant),
            ])
            .unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(verify(&actual, &witness, &[], predicate()), Ok(false));
    }
}
