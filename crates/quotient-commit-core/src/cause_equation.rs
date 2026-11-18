//! Bounded structural equations over public causal atoms.

use crate::{cause_atom::CausalAtom, cause_verdict::CausalInvalidReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EquationOperator {
    All,
    Any,
    ExactlyOne,
    NotFirst,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralEquation {
    pub target: CausalAtom,
    parents: Vec<CausalAtom>,
    pub operator: EquationOperator,
}

impl StructuralEquation {
    pub fn create(
        target: CausalAtom,
        mut parents: Vec<CausalAtom>,
        operator: EquationOperator,
    ) -> Result<Self, CausalInvalidReason> {
        if parents.is_empty()
            || parents
                .iter()
                .any(|parent| parent == &target || parent.slot > target.slot)
        {
            return Err(CausalInvalidReason::Domain);
        }
        parents.sort_unstable();
        if parents.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CausalInvalidReason::NonCanonical);
        }
        Ok(Self {
            target,
            parents,
            operator,
        })
    }

    pub fn parents(&self) -> &[CausalAtom] {
        &self.parents
    }

    pub fn evaluate(&self, values: &[bool]) -> Result<u16, CausalInvalidReason> {
        if values.len() != self.parents.len() {
            return Err(CausalInvalidReason::Domain);
        }
        let value = match self.operator {
            EquationOperator::All => values.iter().all(|value| *value),
            EquationOperator::Any => values.iter().any(|value| *value),
            EquationOperator::ExactlyOne => values.iter().filter(|value| **value).count() == 1,
            EquationOperator::NotFirst => !values[0],
        };
        Ok(u16::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_atom::{create as atom, AtomKind};

    fn at(slot: u64, field: u16) -> CausalAtom {
        atom(slot, AtomKind::Transition, field, 0).unwrap()
    }

    #[test]
    fn equation_evaluates_finite_operator() {
        let equation =
            StructuralEquation::create(at(2, 3), vec![at(1, 1), at(2, 2)], EquationOperator::All)
                .unwrap();
        assert_eq!(equation.evaluate(&[true, true]), Ok(1));
        assert_eq!(equation.evaluate(&[true, false]), Ok(0));
    }

    #[test]
    fn future_parent_is_rejected() {
        assert_eq!(
            StructuralEquation::create(at(1, 1), vec![at(2, 2)], EquationOperator::Any),
            Err(CausalInvalidReason::Domain)
        );
    }

    #[test]
    fn duplicate_parent_is_noncanonical() {
        assert_eq!(
            StructuralEquation::create(at(2, 2), vec![at(1, 1), at(1, 1)], EquationOperator::Any),
            Err(CausalInvalidReason::NonCanonical)
        );
    }
}
