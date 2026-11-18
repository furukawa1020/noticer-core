//! Counterfactual world generation with explicit do-interventions.

use crate::{
    cause_atom::{AtomKind, CausalAtom},
    cause_equation::StructuralEquation,
    cause_evaluator::evaluate,
    cause_intervention::InterventionValue,
    cause_intervention_set::InterventionSet,
    cause_state::CausalState,
    cause_verdict::CausalInvalidReason,
};

pub fn generate(
    actual: &CausalState,
    interventions: &InterventionSet,
    equations: &[StructuralEquation],
) -> Result<CausalState, CausalInvalidReason> {
    let mut atoms = actual.atoms().to_vec();
    for intervention in interventions.as_slice() {
        let index = atoms
            .iter()
            .position(|atom| same_coordinate(*atom, intervention.atom))
            .ok_or(CausalInvalidReason::Domain)?;
        match intervention.replacement {
            InterventionValue::Remove => {
                atoms.remove(index);
            }
            InterventionValue::SetPublicBranch(public_branch) => {
                atoms[index].public_branch = public_branch;
            }
        }
    }
    let outcome = atoms
        .iter()
        .any(|atom| atom.kind == AtomKind::ObserverProjection && atom.public_branch != 0);
    let intervened = CausalState::create(actual.slot, atoms, outcome)?;
    let active_equations: Vec<_> = equations
        .iter()
        .filter(|equation| {
            !interventions
                .as_slice()
                .iter()
                .any(|intervention| same_coordinate(intervention.atom, equation.target))
        })
        .cloned()
        .collect();
    evaluate(&intervened, &active_equations)
}

fn same_coordinate(left: CausalAtom, right: CausalAtom) -> bool {
    left.slot == right.slot && left.kind == right.kind && left.field_id == right.field_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_equation::EquationOperator,
        cause_intervention::{create as intervention, InterventionValue},
    };

    #[test]
    fn intervention_cuts_target_equation() {
        let input = atom(1, AtomKind::PublicInput, 1, 1).unwrap();
        let projection = atom(1, AtomKind::ObserverProjection, 2, 1).unwrap();
        let actual = CausalState::create(1, vec![input, projection], true).unwrap();
        let equation =
            StructuralEquation::create(projection, vec![input], EquationOperator::Any).unwrap();
        let set = InterventionSet::canonicalize(vec![intervention(
            projection,
            InterventionValue::SetPublicBranch(0),
        )
        .unwrap()])
        .unwrap();
        assert!(!generate(&actual, &set, &[equation]).unwrap().outcome);
    }

    #[test]
    fn unknown_intervention_coordinate_is_invalid() {
        let actual = CausalState::create(1, vec![], false).unwrap();
        let unknown = atom(1, AtomKind::Transition, 1, 0).unwrap();
        let set = InterventionSet::canonicalize(vec![intervention(
            unknown,
            InterventionValue::SetPublicBranch(1),
        )
        .unwrap()])
        .unwrap();
        assert_eq!(
            generate(&actual, &set, &[]),
            Err(CausalInvalidReason::Domain)
        );
    }
}
