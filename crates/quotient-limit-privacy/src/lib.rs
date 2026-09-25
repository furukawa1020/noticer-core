#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use quotient_limit_rational::{Rational, RationalError};

pub const DOMAIN_PRIVACY: &[u8] = b"QUOTIENT_LIMIT_PRIVACY_V1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservationId(pub u32);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbabilityMass {
    pub observation: ObservationId,
    pub probability: Rational,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Distribution {
    pub mass: Vec<ProbabilityMass>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyConstraint {
    Exact,
    TotalVariation { tau: Rational },
    RhoDelta { rho: Rational, delta: Rational },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacyAssessment {
    pub satisfied: bool,
    pub total_variation: Rational,
    pub forward_hockey_stick: Rational,
    pub reverse_hockey_stick: Rational,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyError {
    EmptyDistribution,
    NonCanonicalDistribution,
    NegativeProbability,
    ProbabilityMassNotOne,
    InvalidParameter,
    ArithmeticOverflow,
}
impl From<RationalError> for PrivacyError {
    fn from(_: RationalError) -> Self {
        Self::ArithmeticOverflow
    }
}

pub fn assess_pair(
    left: &Distribution,
    right: &Distribution,
    constraint: PrivacyConstraint,
) -> Result<PrivacyAssessment, PrivacyError> {
    validate(left)?;
    validate(right)?;
    let observations = union(left, right);
    let mut l1 = Rational::ZERO;
    for observation in &observations {
        l1 = l1.checked_add(abs(subtract(
            probability(left, *observation),
            probability(right, *observation),
        )?)?)?;
    }
    let tv = l1.checked_mul(Rational::new(1, 2)?)?;
    let (rho, _delta) = match constraint {
        PrivacyConstraint::Exact => (Rational::ONE, Rational::ZERO),
        PrivacyConstraint::TotalVariation { tau } => {
            if tau.is_negative() || tau.checked_cmp(Rational::ONE)? == Ordering::Greater {
                return Err(PrivacyError::InvalidParameter);
            }
            (Rational::ONE, tau)
        }
        PrivacyConstraint::RhoDelta { rho, delta } => {
            if rho.checked_cmp(Rational::ONE)? == Ordering::Less || delta.is_negative() {
                return Err(PrivacyError::InvalidParameter);
            }
            (rho, delta)
        }
    };
    let forward = hockey(left, right, &observations, rho)?;
    let reverse = hockey(right, left, &observations, rho)?;
    let satisfied = match constraint {
        PrivacyConstraint::Exact => tv == Rational::ZERO,
        PrivacyConstraint::TotalVariation { tau } => tv.checked_cmp(tau)? != Ordering::Greater,
        PrivacyConstraint::RhoDelta { delta, .. } => {
            forward.checked_cmp(delta)? != Ordering::Greater
                && reverse.checked_cmp(delta)? != Ordering::Greater
        }
    };
    Ok(PrivacyAssessment {
        satisfied,
        total_variation: tv,
        forward_hockey_stick: forward,
        reverse_hockey_stick: reverse,
    })
}

pub fn equal_prior_bayes_success(tv: Rational) -> Result<Rational, PrivacyError> {
    if tv.is_negative() || tv.checked_cmp(Rational::ONE)? == Ordering::Greater {
        return Err(PrivacyError::InvalidParameter);
    }
    Ok(Rational::new(1, 2)?.checked_mul(Rational::ONE.checked_add(tv)?)?)
}

fn validate(distribution: &Distribution) -> Result<(), PrivacyError> {
    if distribution.mass.is_empty() {
        return Err(PrivacyError::EmptyDistribution);
    }
    if !distribution
        .mass
        .windows(2)
        .all(|x| x[0].observation < x[1].observation)
    {
        return Err(PrivacyError::NonCanonicalDistribution);
    }
    let mut total = Rational::ZERO;
    for item in &distribution.mass {
        if !item.probability.is_canonical() {
            return Err(PrivacyError::NonCanonicalDistribution);
        }
        if item.probability.is_negative() {
            return Err(PrivacyError::NegativeProbability);
        }
        total = total.checked_add(item.probability)?;
    }
    if total != Rational::ONE {
        return Err(PrivacyError::ProbabilityMassNotOne);
    }
    Ok(())
}

fn union(left: &Distribution, right: &Distribution) -> Vec<ObservationId> {
    let mut result: Vec<_> = left
        .mass
        .iter()
        .chain(&right.mass)
        .map(|x| x.observation)
        .collect();
    result.sort();
    result.dedup();
    result
}
fn probability(distribution: &Distribution, observation: ObservationId) -> Rational {
    distribution
        .mass
        .iter()
        .find(|x| x.observation == observation)
        .map_or(Rational::ZERO, |x| x.probability)
}
fn hockey(
    left: &Distribution,
    right: &Distribution,
    observations: &[ObservationId],
    rho: Rational,
) -> Result<Rational, PrivacyError> {
    let mut total = Rational::ZERO;
    for observation in observations {
        let difference = subtract(
            probability(left, *observation),
            rho.checked_mul(probability(right, *observation))?,
        )?;
        if difference.checked_cmp(Rational::ZERO)? == Ordering::Greater {
            total = total.checked_add(difference)?;
        }
    }
    Ok(total)
}
fn subtract(left: Rational, right: Rational) -> Result<Rational, PrivacyError> {
    Ok(left.checked_add(right.checked_neg()?)?)
}
fn abs(value: Rational) -> Result<Rational, PrivacyError> {
    if value.is_negative() {
        Ok(value.checked_neg()?)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn q(n: i128, d: i128) -> Rational {
        Rational::new(n, d).unwrap()
    }
    fn distribution(a: Rational) -> Distribution {
        Distribution {
            mass: vec![
                ProbabilityMass {
                    observation: ObservationId(0),
                    probability: a,
                },
                ProbabilityMass {
                    observation: ObservationId(1),
                    probability: subtract(Rational::ONE, a).unwrap(),
                },
            ],
        }
    }

    #[test]
    fn exact_implies_zero_tv() {
        let d = distribution(q(1, 3));
        let result = assess_pair(&d, &d, PrivacyConstraint::Exact).unwrap();
        assert!(result.satisfied);
        assert_eq!(result.total_variation, Rational::ZERO);
    }
    #[test]
    fn tv_matches_bayes_success() {
        let result = assess_pair(
            &distribution(q(3, 4)),
            &distribution(q(1, 4)),
            PrivacyConstraint::TotalVariation { tau: q(1, 2) },
        )
        .unwrap();
        assert_eq!(result.total_variation, q(1, 2));
        assert_eq!(
            equal_prior_bayes_success(result.total_variation).unwrap(),
            q(3, 4)
        );
    }
    #[test]
    fn rho_delta_requires_both_directions() {
        let result = assess_pair(
            &distribution(q(3, 4)),
            &distribution(q(1, 2)),
            PrivacyConstraint::RhoDelta {
                rho: q(3, 2),
                delta: Rational::ZERO,
            },
        )
        .unwrap();
        assert!(!result.satisfied);
        assert!(
            result.reverse_hockey_stick != Rational::ZERO
                || result.forward_hockey_stick != Rational::ZERO
        );
    }
    #[test]
    fn implicit_nonunit_mass_is_rejected() {
        let invalid = Distribution {
            mass: vec![ProbabilityMass {
                observation: ObservationId(0),
                probability: q(1, 2),
            }],
        };
        assert_eq!(
            assess_pair(&invalid, &distribution(q(1, 2)), PrivacyConstraint::Exact),
            Err(PrivacyError::ProbabilityMassNotOne)
        );
    }
}
