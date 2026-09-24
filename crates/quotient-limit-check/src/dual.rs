use crate::{check_primal, CheckLimits, PrimalCheckError, PrimalProblem, PrimalWitness, Row};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use quotient_limit_rational::{Rational, RationalError};

pub const DOMAIN_DUAL: &[u8] = b"QUOTIENT_LIMIT_DUAL_V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualWitness {
    pub matrix_digest: [u8; 32],
    pub equality_multipliers: Vec<Rational>,
    pub less_equal_multipliers: Vec<Rational>,
    pub claimed_lower_bound: Rational,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptimalityWitness {
    pub primal: PrimalWitness,
    pub dual: DualWitness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualCheckError {
    DigestMismatch,
    DimensionMismatch,
    ResourceLimit,
    NonCanonicalRational,
    InvalidVariable,
    InvalidInequalityMultiplier,
    ReducedCostViolation,
    BoundMismatch,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptimalityCheckError {
    InvalidPrimal(PrimalCheckError),
    InvalidDual(DualCheckError),
    NonZeroGap,
    ComplementarySlacknessViolation,
    ArithmeticOverflow,
}

impl From<RationalError> for DualCheckError {
    fn from(_: RationalError) -> Self {
        Self::ArithmeticOverflow
    }
}

pub fn check_dual(
    problem: &PrimalProblem,
    witness: &DualWitness,
    limits: CheckLimits,
) -> Result<Rational, DualCheckError> {
    if problem.matrix_digest != witness.matrix_digest {
        return Err(DualCheckError::DigestMismatch);
    }
    if witness.equality_multipliers.len() != problem.equalities.len()
        || witness.less_equal_multipliers.len() != problem.less_equal.len()
    {
        return Err(DualCheckError::DimensionMismatch);
    }
    let row_count = problem
        .equalities
        .len()
        .checked_add(problem.less_equal.len())
        .ok_or(DualCheckError::ResourceLimit)?;
    if problem.variable_count as usize > limits.max_variables || row_count > limits.max_rows {
        return Err(DualCheckError::ResourceLimit);
    }
    validate_rational(witness.claimed_lower_bound, limits)?;
    for multiplier in witness
        .equality_multipliers
        .iter()
        .chain(&witness.less_equal_multipliers)
    {
        validate_rational(*multiplier, limits)?;
    }
    for multiplier in &witness.less_equal_multipliers {
        if multiplier.checked_cmp(Rational::ZERO)? == Ordering::Greater {
            return Err(DualCheckError::InvalidInequalityMultiplier);
        }
    }

    let objective = dense_objective(problem, limits)?;
    for variable in 0..problem.variable_count {
        let combined = combined_coefficient(problem, witness, variable)?;
        if combined.checked_cmp(objective[variable as usize])? == Ordering::Greater {
            return Err(DualCheckError::ReducedCostViolation);
        }
    }

    let mut bound = Rational::ZERO;
    for (row, multiplier) in problem.equalities.iter().zip(&witness.equality_multipliers) {
        validate_rational(row.rhs, limits)?;
        bound = bound.checked_add(row.rhs.checked_mul(*multiplier)?)?;
    }
    for (row, multiplier) in problem
        .less_equal
        .iter()
        .zip(&witness.less_equal_multipliers)
    {
        validate_rational(row.rhs, limits)?;
        bound = bound.checked_add(row.rhs.checked_mul(*multiplier)?)?;
    }
    if bound != witness.claimed_lower_bound {
        return Err(DualCheckError::BoundMismatch);
    }
    Ok(bound)
}

pub fn check_certified_optimal(
    problem: &PrimalProblem,
    witness: &OptimalityWitness,
    limits: CheckLimits,
) -> Result<Rational, OptimalityCheckError> {
    let primal = check_primal(problem, &witness.primal, limits)
        .map_err(OptimalityCheckError::InvalidPrimal)?;
    let dual =
        check_dual(problem, &witness.dual, limits).map_err(OptimalityCheckError::InvalidDual)?;
    if primal != dual {
        return Err(OptimalityCheckError::NonZeroGap);
    }
    check_complementary_slackness(problem, witness, limits)?;
    Ok(primal)
}

fn check_complementary_slackness(
    problem: &PrimalProblem,
    witness: &OptimalityWitness,
    limits: CheckLimits,
) -> Result<(), OptimalityCheckError> {
    let objective = dense_objective(problem, limits).map_err(OptimalityCheckError::InvalidDual)?;
    for variable in 0..problem.variable_count {
        let combined = combined_coefficient(problem, &witness.dual, variable)
            .map_err(OptimalityCheckError::InvalidDual)?;
        let reduced = subtract(objective[variable as usize], combined)?;
        let product = reduced
            .checked_mul(witness.primal.values[variable as usize])
            .map_err(|_| OptimalityCheckError::ArithmeticOverflow)?;
        if product != Rational::ZERO {
            return Err(OptimalityCheckError::ComplementarySlacknessViolation);
        }
    }
    for (row, multiplier) in problem
        .less_equal
        .iter()
        .zip(&witness.dual.less_equal_multipliers)
    {
        let activity = evaluate_row(row, &witness.primal.values, limits)
            .map_err(OptimalityCheckError::InvalidDual)?;
        let slack = subtract(row.rhs, activity)?;
        let product = slack
            .checked_mul(*multiplier)
            .map_err(|_| OptimalityCheckError::ArithmeticOverflow)?;
        if product != Rational::ZERO {
            return Err(OptimalityCheckError::ComplementarySlacknessViolation);
        }
    }
    Ok(())
}

fn dense_objective(
    problem: &PrimalProblem,
    limits: CheckLimits,
) -> Result<Vec<Rational>, DualCheckError> {
    let mut objective = vec![Rational::ZERO; problem.variable_count as usize];
    let mut previous = None;
    for term in &problem.objective {
        if previous.is_some_and(|value| value >= term.variable) {
            return Err(DualCheckError::InvalidVariable);
        }
        previous = Some(term.variable);
        validate_rational(term.coefficient, limits)?;
        *objective
            .get_mut(term.variable as usize)
            .ok_or(DualCheckError::InvalidVariable)? = term.coefficient;
    }
    Ok(objective)
}

fn combined_coefficient(
    problem: &PrimalProblem,
    witness: &DualWitness,
    variable: u32,
) -> Result<Rational, DualCheckError> {
    let mut combined = Rational::ZERO;
    for (row, multiplier) in problem.equalities.iter().zip(&witness.equality_multipliers) {
        combined = combined.checked_add(coefficient(row, variable).checked_mul(*multiplier)?)?;
    }
    for (row, multiplier) in problem
        .less_equal
        .iter()
        .zip(&witness.less_equal_multipliers)
    {
        combined = combined.checked_add(coefficient(row, variable).checked_mul(*multiplier)?)?;
    }
    Ok(combined)
}

fn coefficient(row: &Row, variable: u32) -> Rational {
    row.terms
        .iter()
        .find(|term| term.variable == variable)
        .map_or(Rational::ZERO, |term| term.coefficient)
}

fn evaluate_row(
    row: &Row,
    values: &[Rational],
    limits: CheckLimits,
) -> Result<Rational, DualCheckError> {
    let mut total = Rational::ZERO;
    let mut previous = None;
    for term in &row.terms {
        if previous.is_some_and(|value| value >= term.variable) {
            return Err(DualCheckError::InvalidVariable);
        }
        previous = Some(term.variable);
        validate_rational(term.coefficient, limits)?;
        let value = values
            .get(term.variable as usize)
            .ok_or(DualCheckError::InvalidVariable)?;
        total = total.checked_add(term.coefficient.checked_mul(*value)?)?;
    }
    Ok(total)
}

fn validate_rational(value: Rational, limits: CheckLimits) -> Result<(), DualCheckError> {
    if !value.is_canonical() {
        return Err(DualCheckError::NonCanonicalRational);
    }
    if value.bit_length() > limits.max_rational_bits {
        return Err(DualCheckError::ResourceLimit);
    }
    Ok(())
}

fn subtract(left: Rational, right: Rational) -> Result<Rational, OptimalityCheckError> {
    left.checked_add(
        right
            .checked_neg()
            .map_err(|_| OptimalityCheckError::ArithmeticOverflow)?,
    )
    .map_err(|_| OptimalityCheckError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Row, Term};

    fn q(n: i128, d: i128) -> Rational {
        Rational::new(n, d).unwrap()
    }
    fn fixture() -> (PrimalProblem, OptimalityWitness) {
        let digest = [9; 32];
        let problem = PrimalProblem {
            matrix_digest: digest,
            variable_count: 2,
            equalities: vec![Row {
                terms: vec![
                    Term {
                        variable: 0,
                        coefficient: Rational::ONE,
                    },
                    Term {
                        variable: 1,
                        coefficient: Rational::ONE,
                    },
                ],
                rhs: Rational::ONE,
            }],
            less_equal: vec![],
            objective: vec![
                Term {
                    variable: 0,
                    coefficient: Rational::ONE,
                },
                Term {
                    variable: 1,
                    coefficient: q(2, 1),
                },
            ],
        };
        let primal = PrimalWitness {
            matrix_digest: digest,
            values: vec![Rational::ONE, Rational::ZERO],
            claimed_objective: Rational::ONE,
        };
        let dual = DualWitness {
            matrix_digest: digest,
            equality_multipliers: vec![Rational::ONE],
            less_equal_multipliers: vec![],
            claimed_lower_bound: Rational::ONE,
        };
        (problem, OptimalityWitness { primal, dual })
    }

    #[test]
    fn exact_zero_gap_certifies_optimality() {
        let (problem, witness) = fixture();
        assert_eq!(
            check_certified_optimal(&problem, &witness, CheckLimits::default()),
            Ok(Rational::ONE)
        );
    }

    #[test]
    fn inflated_bound_is_rejected() {
        let (problem, mut witness) = fixture();
        witness.dual.claimed_lower_bound = q(2, 1);
        assert_eq!(
            check_dual(&problem, &witness.dual, CheckLimits::default()),
            Err(DualCheckError::BoundMismatch)
        );
    }

    #[test]
    fn reduced_cost_violation_is_rejected() {
        let (problem, mut witness) = fixture();
        witness.dual.equality_multipliers[0] = q(3, 1);
        witness.dual.claimed_lower_bound = q(3, 1);
        assert_eq!(
            check_dual(&problem, &witness.dual, CheckLimits::default()),
            Err(DualCheckError::ReducedCostViolation)
        );
    }
}
