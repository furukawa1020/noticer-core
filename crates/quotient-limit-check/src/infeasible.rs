use crate::{CheckLimits, PrimalProblem, Row};
use alloc::vec::Vec;
use core::cmp::Ordering;
use quotient_limit_rational::{Rational, RationalError};

pub const DOMAIN_FARKAS: &[u8] = b"QUOTIENT_LIMIT_FARKAS_V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FarkasWitness {
    pub matrix_digest: [u8; 32],
    pub equality_multipliers: Vec<Rational>,
    pub less_equal_multipliers: Vec<Rational>,
    pub claimed_contradiction: Rational,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConstraintCategory {
    Causality,
    ProbabilityFlow,
    Privacy,
    Utility,
    Deadline,
    FaultSafety,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConstraintLabel {
    pub category: ConstraintCategory,
    pub stable_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreMinimality {
    NotEstablished,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplanationCore {
    pub constraints: Vec<ConstraintLabel>,
    pub minimality: CoreMinimality,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfeasibilityCheckError {
    DigestMismatch,
    DimensionMismatch,
    ResourceLimit,
    NonCanonicalRational,
    InvalidVariable,
    InvalidInequalityMultiplier,
    ColumnCombinationViolation,
    NonPositiveContradiction,
    ContradictionMismatch,
    LabelMismatch,
    ArithmeticOverflow,
}

impl From<RationalError> for InfeasibilityCheckError {
    fn from(_: RationalError) -> Self {
        Self::ArithmeticOverflow
    }
}

pub fn check_farkas_infeasible(
    problem: &PrimalProblem,
    witness: &FarkasWitness,
    limits: CheckLimits,
) -> Result<Rational, InfeasibilityCheckError> {
    if problem.matrix_digest != witness.matrix_digest {
        return Err(InfeasibilityCheckError::DigestMismatch);
    }
    if witness.equality_multipliers.len() != problem.equalities.len()
        || witness.less_equal_multipliers.len() != problem.less_equal.len()
    {
        return Err(InfeasibilityCheckError::DimensionMismatch);
    }
    let row_count = problem
        .equalities
        .len()
        .checked_add(problem.less_equal.len())
        .ok_or(InfeasibilityCheckError::ResourceLimit)?;
    if problem.variable_count as usize > limits.max_variables || row_count > limits.max_rows {
        return Err(InfeasibilityCheckError::ResourceLimit);
    }
    validate(witness.claimed_contradiction, limits)?;
    for multiplier in witness
        .equality_multipliers
        .iter()
        .chain(&witness.less_equal_multipliers)
    {
        validate(*multiplier, limits)?;
    }
    for multiplier in &witness.less_equal_multipliers {
        if multiplier.checked_cmp(Rational::ZERO)? == Ordering::Greater {
            return Err(InfeasibilityCheckError::InvalidInequalityMultiplier);
        }
    }
    for variable in 0..problem.variable_count {
        let mut combined = Rational::ZERO;
        for (row, multiplier) in problem.equalities.iter().zip(&witness.equality_multipliers) {
            combined =
                combined.checked_add(coefficient(row, variable)?.checked_mul(*multiplier)?)?;
        }
        for (row, multiplier) in problem
            .less_equal
            .iter()
            .zip(&witness.less_equal_multipliers)
        {
            combined =
                combined.checked_add(coefficient(row, variable)?.checked_mul(*multiplier)?)?;
        }
        if combined.checked_cmp(Rational::ZERO)? == Ordering::Greater {
            return Err(InfeasibilityCheckError::ColumnCombinationViolation);
        }
    }
    let mut contradiction = Rational::ZERO;
    for (row, multiplier) in problem.equalities.iter().zip(&witness.equality_multipliers) {
        validate(row.rhs, limits)?;
        contradiction = contradiction.checked_add(row.rhs.checked_mul(*multiplier)?)?;
    }
    for (row, multiplier) in problem
        .less_equal
        .iter()
        .zip(&witness.less_equal_multipliers)
    {
        validate(row.rhs, limits)?;
        contradiction = contradiction.checked_add(row.rhs.checked_mul(*multiplier)?)?;
    }
    if contradiction != witness.claimed_contradiction {
        return Err(InfeasibilityCheckError::ContradictionMismatch);
    }
    if contradiction.checked_cmp(Rational::ZERO)? != Ordering::Greater {
        return Err(InfeasibilityCheckError::NonPositiveContradiction);
    }
    Ok(contradiction)
}

pub fn explain_farkas_support(
    problem: &PrimalProblem,
    witness: &FarkasWitness,
    equality_labels: &[ConstraintLabel],
    less_equal_labels: &[ConstraintLabel],
    limits: CheckLimits,
) -> Result<ExplanationCore, InfeasibilityCheckError> {
    check_farkas_infeasible(problem, witness, limits)?;
    if equality_labels.len() != problem.equalities.len()
        || less_equal_labels.len() != problem.less_equal.len()
    {
        return Err(InfeasibilityCheckError::LabelMismatch);
    }
    let mut constraints = Vec::new();
    for (label, multiplier) in equality_labels.iter().zip(&witness.equality_multipliers) {
        if *multiplier != Rational::ZERO {
            constraints.push(*label);
        }
    }
    for (label, multiplier) in less_equal_labels
        .iter()
        .zip(&witness.less_equal_multipliers)
    {
        if *multiplier != Rational::ZERO {
            constraints.push(*label);
        }
    }
    constraints.sort();
    constraints.dedup();
    Ok(ExplanationCore {
        constraints,
        minimality: CoreMinimality::NotEstablished,
    })
}

fn coefficient(row: &Row, variable: u32) -> Result<Rational, InfeasibilityCheckError> {
    let mut previous = None;
    for term in &row.terms {
        if previous.is_some_and(|value| value >= term.variable) {
            return Err(InfeasibilityCheckError::InvalidVariable);
        }
        previous = Some(term.variable);
        if term.variable == variable {
            return Ok(term.coefficient);
        }
    }
    Ok(Rational::ZERO)
}

fn validate(value: Rational, limits: CheckLimits) -> Result<(), InfeasibilityCheckError> {
    if !value.is_canonical() {
        return Err(InfeasibilityCheckError::NonCanonicalRational);
    }
    if value.bit_length() > limits.max_rational_bits {
        return Err(InfeasibilityCheckError::ResourceLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrimalProblem, Row, Term};
    use alloc::vec;

    fn infeasible_fixture() -> (PrimalProblem, FarkasWitness) {
        let digest = [11; 32];
        let problem = PrimalProblem {
            matrix_digest: digest,
            variable_count: 1,
            equalities: vec![Row {
                terms: vec![Term {
                    variable: 0,
                    coefficient: Rational::ONE,
                }],
                rhs: Rational::new(-1, 1).unwrap(),
            }],
            less_equal: vec![],
            objective: vec![],
        };
        let witness = FarkasWitness {
            matrix_digest: digest,
            equality_multipliers: vec![Rational::new(-1, 1).unwrap()],
            less_equal_multipliers: vec![],
            claimed_contradiction: Rational::ONE,
        };
        (problem, witness)
    }

    #[test]
    fn exact_farkas_contradiction_is_accepted() {
        let (problem, witness) = infeasible_fixture();
        assert_eq!(
            check_farkas_infeasible(&problem, &witness, CheckLimits::default()),
            Ok(Rational::ONE)
        );
    }

    #[test]
    fn mutated_contradiction_is_rejected() {
        let (problem, mut witness) = infeasible_fixture();
        witness.claimed_contradiction = Rational::new(2, 1).unwrap();
        assert_eq!(
            check_farkas_infeasible(&problem, &witness, CheckLimits::default()),
            Err(InfeasibilityCheckError::ContradictionMismatch)
        );
    }

    #[test]
    fn explanation_is_support_not_false_minimal_core() {
        let (problem, witness) = infeasible_fixture();
        let label = ConstraintLabel {
            category: ConstraintCategory::Utility,
            stable_id: 7,
        };
        let core =
            explain_farkas_support(&problem, &witness, &[label], &[], CheckLimits::default())
                .unwrap();
        assert_eq!(core.constraints, vec![label]);
        assert_eq!(core.minimality, CoreMinimality::NotEstablished);
    }
}
