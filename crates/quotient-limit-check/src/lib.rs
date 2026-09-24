#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use quotient_limit_rational::{Rational, RationalError};

pub const DOMAIN_PRIMAL: &[u8] = b"QUOTIENT_LIMIT_PRIMAL_V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Term {
    pub variable: u32,
    pub coefficient: Rational,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub terms: Vec<Term>,
    pub rhs: Rational,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimalProblem {
    pub matrix_digest: [u8; 32],
    pub variable_count: u32,
    pub equalities: Vec<Row>,
    pub less_equal: Vec<Row>,
    pub objective: Vec<Term>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimalWitness {
    pub matrix_digest: [u8; 32],
    pub values: Vec<Rational>,
    pub claimed_objective: Rational,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckLimits {
    pub max_variables: usize,
    pub max_rows: usize,
    pub max_terms: usize,
    pub max_rational_bits: u32,
}
impl Default for CheckLimits {
    fn default() -> Self {
        Self {
            max_variables: 10_000_000,
            max_rows: 20_000_000,
            max_terms: 200_000_000,
            max_rational_bits: 8192,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimalCheckError {
    DigestMismatch,
    ResourceLimit,
    DimensionMismatch,
    NonCanonicalRational,
    InvalidVariable,
    NegativeVariable,
    EqualityViolation,
    InequalityViolation,
    ObjectiveMismatch,
    ArithmeticOverflow,
}
impl From<RationalError> for PrimalCheckError {
    fn from(_: RationalError) -> Self {
        Self::ArithmeticOverflow
    }
}

pub fn check_primal(
    problem: &PrimalProblem,
    witness: &PrimalWitness,
    limits: CheckLimits,
) -> Result<Rational, PrimalCheckError> {
    if problem.matrix_digest != witness.matrix_digest {
        return Err(PrimalCheckError::DigestMismatch);
    }
    if problem.variable_count as usize != witness.values.len() {
        return Err(PrimalCheckError::DimensionMismatch);
    }
    let rows = problem
        .equalities
        .len()
        .checked_add(problem.less_equal.len())
        .ok_or(PrimalCheckError::ResourceLimit)?;
    let terms = problem
        .equalities
        .iter()
        .chain(&problem.less_equal)
        .map(|row| row.terms.len())
        .chain(core::iter::once(problem.objective.len()))
        .try_fold(0usize, |sum, count| {
            sum.checked_add(count)
                .ok_or(PrimalCheckError::ResourceLimit)
        })?;
    if witness.values.len() > limits.max_variables
        || rows > limits.max_rows
        || terms > limits.max_terms
    {
        return Err(PrimalCheckError::ResourceLimit);
    }
    for value in witness
        .values
        .iter()
        .chain(core::iter::once(&witness.claimed_objective))
    {
        validate_rational(*value, limits)?;
        if value.is_negative() {
            return Err(PrimalCheckError::NegativeVariable);
        }
    }
    for row in &problem.equalities {
        if evaluate(row, &witness.values, limits)? != row.rhs {
            return Err(PrimalCheckError::EqualityViolation);
        }
    }
    for row in &problem.less_equal {
        if evaluate(row, &witness.values, limits)?.checked_cmp(row.rhs)? == Ordering::Greater {
            return Err(PrimalCheckError::InequalityViolation);
        }
    }
    let objective = evaluate_terms(&problem.objective, &witness.values, limits)?;
    if objective != witness.claimed_objective {
        return Err(PrimalCheckError::ObjectiveMismatch);
    }
    Ok(objective)
}

fn evaluate(
    row: &Row,
    values: &[Rational],
    limits: CheckLimits,
) -> Result<Rational, PrimalCheckError> {
    validate_rational(row.rhs, limits)?;
    evaluate_terms(&row.terms, values, limits)
}
fn evaluate_terms(
    terms: &[Term],
    values: &[Rational],
    limits: CheckLimits,
) -> Result<Rational, PrimalCheckError> {
    let mut total = Rational::ZERO;
    let mut previous = None;
    for term in terms {
        if previous.is_some_and(|value| value >= term.variable) {
            return Err(PrimalCheckError::InvalidVariable);
        }
        previous = Some(term.variable);
        validate_rational(term.coefficient, limits)?;
        let value = *values
            .get(term.variable as usize)
            .ok_or(PrimalCheckError::InvalidVariable)?;
        total = total.checked_add(term.coefficient.checked_mul(value)?)?;
        validate_rational(total, limits)?;
    }
    Ok(total)
}
fn validate_rational(value: Rational, limits: CheckLimits) -> Result<(), PrimalCheckError> {
    if !value.is_canonical() {
        return Err(PrimalCheckError::NonCanonicalRational);
    }
    if value.bit_length() > limits.max_rational_bits {
        return Err(PrimalCheckError::ResourceLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn q(n: i128, d: i128) -> Rational {
        Rational::new(n, d).unwrap()
    }
    fn fixture() -> (PrimalProblem, PrimalWitness) {
        let digest = [7; 32];
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
            less_equal: vec![Row {
                terms: vec![Term {
                    variable: 0,
                    coefficient: Rational::ONE,
                }],
                rhs: q(3, 4),
            }],
            objective: vec![
                Term {
                    variable: 0,
                    coefficient: q(2, 1),
                },
                Term {
                    variable: 1,
                    coefficient: Rational::ONE,
                },
            ],
        };
        let witness = PrimalWitness {
            matrix_digest: digest,
            values: vec![q(1, 4), q(3, 4)],
            claimed_objective: q(5, 4),
        };
        (problem, witness)
    }
    #[test]
    fn valid_primal_is_accepted_exactly() {
        let (p, w) = fixture();
        assert_eq!(check_primal(&p, &w, CheckLimits::default()), Ok(q(5, 4)));
    }
    #[test]
    fn objective_mutation_is_rejected() {
        let (p, mut w) = fixture();
        w.claimed_objective = q(6, 4);
        assert_eq!(
            check_primal(&p, &w, CheckLimits::default()),
            Err(PrimalCheckError::ObjectiveMismatch)
        );
    }
    #[test]
    fn digest_substitution_is_rejected() {
        let (p, mut w) = fixture();
        w.matrix_digest[0] ^= 1;
        assert_eq!(
            check_primal(&p, &w, CheckLimits::default()),
            Err(PrimalCheckError::DigestMismatch)
        );
    }
    #[test]
    fn negative_probability_is_rejected() {
        let (p, mut w) = fixture();
        w.values[0] = q(-1, 4);
        assert_eq!(
            check_primal(&p, &w, CheckLimits::default()),
            Err(PrimalCheckError::NegativeVariable)
        );
    }
}

mod dual;
pub use dual::{
    check_certified_optimal, check_dual, DualCheckError, DualWitness, OptimalityCheckError,
    OptimalityWitness, DOMAIN_DUAL,
};
