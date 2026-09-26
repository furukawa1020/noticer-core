#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;
use quotient_limit_privacy::{assess_pair, Distribution, ObservationId, PrivacyConstraint};
use quotient_limit_rational::{Rational, RationalError};

pub const MAX_ALPHA_ORDERS: usize = 64;
pub const MAX_CASES: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileCase {
    pub public_state: u64,
    pub left_action_semantics_hash: [u8; 32],
    pub right_action_semantics_hash: [u8; 32],
    pub left: Distribution,
    pub right: Distribution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationRequest {
    pub source_certificate_hash: [u8; 32],
    pub action_quotient_hash: [u8; 32],
    pub alpha_orders: Vec<u16>,
    pub cases: Vec<ProfileCase>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactMomentBound {
    pub alpha: u16,
    pub forward_upper: Rational,
    pub reverse_upper: Rational,
    pub log_q64_64_upper: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DerivedProfile {
    Bounded {
        source_certificate_hash: [u8; 32],
        action_quotient_hash: [u8; 32],
        moments: Vec<ExactMomentBound>,
        exact_aetp_zero_profile: bool,
    },
    Unbounded {
        source_certificate_hash: [u8; 32],
        action_quotient_hash: [u8; 32],
        public_state: u64,
        observation: ObservationId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivationError {
    ZeroSourceHash,
    ZeroActionQuotientHash,
    EmptyOrders,
    InvalidOrder,
    NonCanonicalOrders,
    EmptyCases,
    ResourceLimit,
    ActionSemanticsMismatch,
    InvalidDistribution,
    ArithmeticOverflow,
    MomentBelowOne,
}

impl From<RationalError> for DerivationError {
    fn from(_: RationalError) -> Self {
        Self::ArithmeticOverflow
    }
}

pub fn derive_exact_profile(
    request: &DerivationRequest,
) -> Result<DerivedProfile, DerivationError> {
    validate_request(request)?;
    let mut moments = Vec::with_capacity(request.alpha_orders.len());

    for &alpha in &request.alpha_orders {
        let mut forward_upper = Rational::ONE;
        let mut reverse_upper = Rational::ONE;
        for case in &request.cases {
            validate_case(case, request.action_quotient_hash)?;
            if let Some(observation) = support_mismatch(&case.left, &case.right) {
                return Ok(DerivedProfile::Unbounded {
                    source_certificate_hash: request.source_certificate_hash,
                    action_quotient_hash: request.action_quotient_hash,
                    public_state: case.public_state,
                    observation,
                });
            }
            let forward = exact_moment(&case.left, &case.right, alpha)?;
            let reverse = exact_moment(&case.right, &case.left, alpha)?;
            if forward.checked_cmp(forward_upper)? == Ordering::Greater {
                forward_upper = forward;
            }
            if reverse.checked_cmp(reverse_upper)? == Ordering::Greater {
                reverse_upper = reverse;
            }
        }
        let worst = if forward_upper.checked_cmp(reverse_upper)? == Ordering::Greater {
            forward_upper
        } else {
            reverse_upper
        };
        moments.push(ExactMomentBound {
            alpha,
            forward_upper,
            reverse_upper,
            log_q64_64_upper: conservative_log_upper(worst)?,
        });
    }

    let exact_aetp_zero_profile = moments.iter().all(|moment| {
        moment.forward_upper == Rational::ONE
            && moment.reverse_upper == Rational::ONE
            && moment.log_q64_64_upper == 0
    });
    Ok(DerivedProfile::Bounded {
        source_certificate_hash: request.source_certificate_hash,
        action_quotient_hash: request.action_quotient_hash,
        moments,
        exact_aetp_zero_profile,
    })
}

fn validate_request(request: &DerivationRequest) -> Result<(), DerivationError> {
    if request.source_certificate_hash == [0; 32] {
        return Err(DerivationError::ZeroSourceHash);
    }
    if request.action_quotient_hash == [0; 32] {
        return Err(DerivationError::ZeroActionQuotientHash);
    }
    if request.alpha_orders.is_empty() {
        return Err(DerivationError::EmptyOrders);
    }
    if request.alpha_orders.len() > MAX_ALPHA_ORDERS || request.cases.len() > MAX_CASES {
        return Err(DerivationError::ResourceLimit);
    }
    if request.cases.is_empty() {
        return Err(DerivationError::EmptyCases);
    }
    let mut previous = 1;
    for &alpha in &request.alpha_orders {
        if alpha <= 1 {
            return Err(DerivationError::InvalidOrder);
        }
        if alpha <= previous {
            return Err(DerivationError::NonCanonicalOrders);
        }
        previous = alpha;
    }
    Ok(())
}

fn validate_case(case: &ProfileCase, expected: [u8; 32]) -> Result<(), DerivationError> {
    if case.left_action_semantics_hash != expected
        || case.right_action_semantics_hash != expected
        || case.left_action_semantics_hash != case.right_action_semantics_hash
    {
        return Err(DerivationError::ActionSemanticsMismatch);
    }
    assess_pair(
        &case.left,
        &case.right,
        PrivacyConstraint::TotalVariation { tau: Rational::ONE },
    )
    .map_err(|_| DerivationError::InvalidDistribution)?;
    Ok(())
}

fn support_mismatch(left: &Distribution, right: &Distribution) -> Option<ObservationId> {
    left.mass
        .iter()
        .chain(&right.mass)
        .map(|mass| mass.observation)
        .find(|observation| {
            let left_probability = probability(left, *observation);
            let right_probability = probability(right, *observation);
            (left_probability == Rational::ZERO) != (right_probability == Rational::ZERO)
        })
}

fn exact_moment(
    left: &Distribution,
    right: &Distribution,
    alpha: u16,
) -> Result<Rational, DerivationError> {
    let mut total = Rational::ZERO;
    for mass in &left.mass {
        if mass.probability == Rational::ZERO {
            continue;
        }
        let right_probability = probability(right, mass.observation);
        if right_probability == Rational::ZERO {
            return Err(DerivationError::ArithmeticOverflow);
        }
        let numerator = checked_pow(mass.probability, alpha)?;
        let denominator = checked_pow(right_probability, alpha - 1)?;
        total = total.checked_add(checked_div(numerator, denominator)?)?;
    }
    if total.checked_cmp(Rational::ONE)? == Ordering::Less {
        return Err(DerivationError::MomentBelowOne);
    }
    Ok(total)
}

fn probability(distribution: &Distribution, observation: ObservationId) -> Rational {
    distribution
        .mass
        .iter()
        .find(|mass| mass.observation == observation)
        .map_or(Rational::ZERO, |mass| mass.probability)
}

fn checked_pow(base: Rational, exponent: u16) -> Result<Rational, DerivationError> {
    let mut result = Rational::ONE;
    for _ in 0..exponent {
        result = result.checked_mul(base)?;
    }
    Ok(result)
}

fn checked_div(numerator: Rational, denominator: Rational) -> Result<Rational, DerivationError> {
    if denominator == Rational::ZERO {
        return Err(DerivationError::ArithmeticOverflow);
    }
    let top = numerator
        .numerator()
        .checked_mul(denominator.denominator())
        .ok_or(DerivationError::ArithmeticOverflow)?;
    let bottom = numerator
        .denominator()
        .checked_mul(denominator.numerator())
        .ok_or(DerivationError::ArithmeticOverflow)?;
    Ok(Rational::new(top, bottom)?)
}

fn conservative_log_upper(moment: Rational) -> Result<u128, DerivationError> {
    if moment.checked_cmp(Rational::ONE)? == Ordering::Less {
        return Err(DerivationError::MomentBelowOne);
    }
    if moment == Rational::ONE {
        return Ok(0);
    }
    let numerator =
        u128::try_from(moment.numerator()).map_err(|_| DerivationError::ArithmeticOverflow)?;
    let denominator =
        u128::try_from(moment.denominator()).map_err(|_| DerivationError::ArithmeticOverflow)?;
    let mut scaled = denominator;
    let mut bits = 0_u32;
    while scaled < numerator {
        scaled = scaled
            .checked_mul(2)
            .ok_or(DerivationError::ArithmeticOverflow)?;
        bits = bits
            .checked_add(1)
            .ok_or(DerivationError::ArithmeticOverflow)?;
    }
    u128::from(bits)
        .checked_shl(64)
        .ok_or(DerivationError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quotient_limit_privacy::ProbabilityMass;

    fn q(numerator: i128, denominator: i128) -> Rational {
        Rational::new(numerator, denominator).unwrap()
    }

    fn distribution(first: Rational, second: Rational) -> Distribution {
        Distribution {
            mass: vec![
                ProbabilityMass {
                    observation: ObservationId(0),
                    probability: first,
                },
                ProbabilityMass {
                    observation: ObservationId(1),
                    probability: second,
                },
            ],
        }
    }

    fn request(left: Distribution, right: Distribution) -> DerivationRequest {
        DerivationRequest {
            source_certificate_hash: [9; 32],
            action_quotient_hash: [7; 32],
            alpha_orders: vec![2, 3, 4],
            cases: vec![ProfileCase {
                public_state: 11,
                left_action_semantics_hash: [7; 32],
                right_action_semantics_hash: [7; 32],
                left,
                right,
            }],
        }
    }

    #[test]
    fn exact_aetp_derives_zero_profile_from_equal_distributions() {
        let distribution = distribution(q(1, 3), q(2, 3));
        let result = derive_exact_profile(&request(distribution.clone(), distribution)).unwrap();
        let DerivedProfile::Bounded {
            moments,
            exact_aetp_zero_profile,
            ..
        } = result
        else {
            panic!("expected bounded profile");
        };
        assert!(exact_aetp_zero_profile);
        assert!(moments.iter().all(|moment| {
            moment.forward_upper == Rational::ONE
                && moment.reverse_upper == Rational::ONE
                && moment.log_q64_64_upper == 0
        }));
    }

    #[test]
    fn asymmetric_alpha_two_moments_are_exact_and_bidirectional() {
        let mut request = request(
            distribution(q(3, 4), q(1, 4)),
            distribution(q(1, 2), q(1, 2)),
        );
        request.alpha_orders = vec![2];
        let DerivedProfile::Bounded { moments, .. } = derive_exact_profile(&request).unwrap()
        else {
            panic!("expected bounded profile");
        };
        assert_eq!(moments[0].forward_upper, q(5, 4));
        assert_eq!(moments[0].reverse_upper, q(4, 3));
        assert!(moments[0].log_q64_64_upper > 0);
    }

    #[test]
    fn support_mismatch_is_unbounded_not_large_finite() {
        let result = derive_exact_profile(&request(
            distribution(Rational::ONE, Rational::ZERO),
            distribution(q(1, 2), q(1, 2)),
        ))
        .unwrap();
        assert_eq!(
            result,
            DerivedProfile::Unbounded {
                source_certificate_hash: [9; 32],
                action_quotient_hash: [7; 32],
                public_state: 11,
                observation: ObservationId(1),
            }
        );
    }

    #[test]
    fn supremum_is_taken_across_public_states() {
        let mut request = request(
            distribution(q(1, 2), q(1, 2)),
            distribution(q(1, 2), q(1, 2)),
        );
        request.alpha_orders = vec![2];
        request.cases.push(ProfileCase {
            public_state: 12,
            left_action_semantics_hash: [7; 32],
            right_action_semantics_hash: [7; 32],
            left: distribution(q(3, 4), q(1, 4)),
            right: distribution(q(1, 2), q(1, 2)),
        });
        let DerivedProfile::Bounded { moments, .. } = derive_exact_profile(&request).unwrap()
        else {
            panic!("expected bounded profile");
        };
        assert_eq!(moments[0].forward_upper, q(5, 4));
        assert_eq!(moments[0].reverse_upper, q(4, 3));
    }

    #[test]
    fn action_semantics_mismatch_is_rejected_before_derivation() {
        let mut request = request(
            distribution(q(1, 2), q(1, 2)),
            distribution(q(1, 2), q(1, 2)),
        );
        request.cases[0].right_action_semantics_hash = [8; 32];
        assert_eq!(
            derive_exact_profile(&request),
            Err(DerivationError::ActionSemanticsMismatch)
        );
    }

    #[test]
    fn order_grid_is_nonempty_sorted_and_bounded() {
        let mut request = request(
            distribution(q(1, 2), q(1, 2)),
            distribution(q(1, 2), q(1, 2)),
        );
        request.alpha_orders = vec![2, 2];
        assert_eq!(
            derive_exact_profile(&request),
            Err(DerivationError::NonCanonicalOrders)
        );
        request.alpha_orders = vec![];
        assert_eq!(
            derive_exact_profile(&request),
            Err(DerivationError::EmptyOrders)
        );
    }
}
