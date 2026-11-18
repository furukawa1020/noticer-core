//! Deterministic evaluator for bounded structural causal models.

use crate::{
    cause_atom::{AtomKind, CausalAtom},
    cause_equation::StructuralEquation,
    cause_state::CausalState,
    cause_verdict::CausalInvalidReason,
};

pub fn evaluate(
    actual: &CausalState,
    equations: &[StructuralEquation],
) -> Result<CausalState, CausalInvalidReason> {
    let mut ordered = equations.to_vec();
    ordered.sort_by_key(|equation| equation.target);
    if ordered
        .windows(2)
        .any(|pair| same_coordinate(pair[0].target, pair[1].target))
    {
        return Err(CausalInvalidReason::NonCanonical);
    }
    let mut values = actual.atoms().to_vec();
    for equation in ordered {
        let parent_values: Result<Vec<_>, _> = equation
            .parents()
            .iter()
            .map(|parent| {
                values
                    .iter()
                    .rev()
                    .find(|value| same_coordinate(**value, *parent))
                    .map(|value| value.public_branch != 0)
                    .ok_or(CausalInvalidReason::Domain)
            })
            .collect();
        let branch = equation.evaluate(&parent_values?)?;
        values.retain(|value| !same_coordinate(*value, equation.target));
        values.push(CausalAtom {
            public_branch: branch,
            ..equation.target
        });
    }
    let outcome = values
        .iter()
        .any(|atom| atom.kind == AtomKind::ObserverProjection && atom.public_branch != 0);
    CausalState::create(actual.slot, values, outcome)
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
    };

    fn at(slot: u64, kind: AtomKind, field: u16, branch: u16) -> CausalAtom {
        atom(slot, kind, field, branch).unwrap()
    }

    #[test]
    fn evaluation_updates_counterfactual_outcome() {
        let input = at(1, AtomKind::PublicInput, 1, 0);
        let projection = at(1, AtomKind::ObserverProjection, 2, 1);
        let actual = CausalState::create(1, vec![input, projection], true).unwrap();
        let equation =
            StructuralEquation::create(projection, vec![input], EquationOperator::Any).unwrap();
        let counterfactual = evaluate(&actual, &[equation]).unwrap();
        assert!(!counterfactual.outcome);
    }

    #[test]
    fn missing_parent_is_invalid() {
        let input = at(1, AtomKind::PublicInput, 1, 0);
        let projection = at(1, AtomKind::ObserverProjection, 2, 1);
        let actual = CausalState::create(1, vec![projection], true).unwrap();
        let equation =
            StructuralEquation::create(projection, vec![input], EquationOperator::Any).unwrap();
        assert_eq!(
            evaluate(&actual, &[equation]),
            Err(CausalInvalidReason::Domain)
        );
    }
}
