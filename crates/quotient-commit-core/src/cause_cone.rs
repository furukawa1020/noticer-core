//! Backward causal-cone extraction from structural equations.

use std::collections::BTreeSet;

use crate::{
    cause_atom::CausalAtom, cause_equation::StructuralEquation,
    cause_verdict::CausalInconclusiveReason,
};

pub fn extract(
    equations: &[StructuralEquation],
    roots: &[CausalAtom],
    maximum_atoms: usize,
) -> Result<Vec<CausalAtom>, CausalInconclusiveReason> {
    let mut cone = BTreeSet::new();
    let mut frontier: Vec<_> = roots.to_vec();
    frontier.sort_unstable_by(|left, right| right.cmp(left));
    while let Some(atom) = frontier.pop() {
        if !cone.insert(atom) {
            continue;
        }
        if cone.len() > maximum_atoms {
            return Err(CausalInconclusiveReason::NodeLimit);
        }
        if let Some(equation) = equations.iter().find(|equation| equation.target == atom) {
            let mut parents = equation.parents().to_vec();
            parents.sort_unstable_by(|left, right| right.cmp(left));
            frontier.extend(parents);
        }
    }
    Ok(cone.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_equation::EquationOperator,
    };

    fn at(field: u16) -> CausalAtom {
        atom(1, AtomKind::Transition, field, 0).unwrap()
    }

    #[test]
    fn extracts_transitive_parent_cone() {
        let first = StructuralEquation::create(at(2), vec![at(1)], EquationOperator::Any).unwrap();
        let second = StructuralEquation::create(at(3), vec![at(2)], EquationOperator::Any).unwrap();
        assert_eq!(
            extract(&[second, first], &[at(3)], 3),
            Ok(vec![at(1), at(2), at(3)])
        );
    }

    #[test]
    fn bounded_extraction_is_inconclusive() {
        let equation =
            StructuralEquation::create(at(3), vec![at(1), at(2)], EquationOperator::Any).unwrap();
        assert_eq!(
            extract(&[equation], &[at(3)], 2),
            Err(CausalInconclusiveReason::NodeLimit)
        );
    }
}
