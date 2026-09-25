#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;
use quotient_limit_rational::{Rational, RationalError};

pub const FROZEN_FAULT_FAMILY_GATE: usize = 4;
pub const FROZEN_COLLUSION_SERVICE_GATE: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultTrace {
    pub family_id: u32,
    pub public_events: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultScenario {
    pub public_fault_trace: FaultTrace,
    pub recoverable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioEvaluation {
    pub scenario: FaultScenario,
    pub utility_satisfied: bool,
    pub cost: Rational,
    pub public_prior: Option<Rational>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostObjective {
    WorstCase,
    ExpectedUnderExplicitPublicPrior,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MechanismEvaluation {
    pub mechanism_id: u32,
    pub scenarios: Vec<ScenarioEvaluation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultAssessment {
    pub objective_value: Rational,
    pub worst_case_cost: Rational,
    pub fault_family_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RobustOptimum {
    pub mechanism_id: u32,
    pub assessment: FaultAssessment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomnessMode {
    Independent,
    Shared,
    Correlated,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct JointServiceTrace {
    pub services: Vec<Vec<u32>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointMass {
    pub trace: JointServiceTrace,
    pub probability: Rational,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointDistribution {
    pub outcomes: Vec<JointMass>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollusionAssessment {
    pub randomness_mode: RandomnessMode,
    pub service_count: usize,
    pub marginal_total_variation: Vec<Rational>,
    pub maximum_marginal_total_variation: Rational,
    pub joint_total_variation: Rational,
    pub correlation_leakage: Rational,
    pub marginal_certificate_is_collusion_safe: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RobustError {
    EmptyScenarioSet,
    EmptyCandidateSet,
    NegativeCost,
    MissingPublicPrior,
    NegativePublicPrior,
    PublicPriorNotNormalized,
    RecoverableUtilityViolation { family_id: u32 },
    InsufficientFaultFamilies { required: usize, actual: usize },
    NoRobustCandidate,
    EmptyDistribution,
    EmptyServiceSet,
    InconsistentServiceCount,
    InsufficientServices { required: usize, actual: usize },
    NonCanonicalOutcomeOrder,
    NegativeProbability,
    DistributionNotNormalized,
    Arithmetic(RationalError),
}

impl From<RationalError> for RobustError {
    fn from(value: RationalError) -> Self {
        Self::Arithmetic(value)
    }
}

pub fn assess_faults(
    scenarios: &[ScenarioEvaluation],
    objective: CostObjective,
    minimum_fault_families: usize,
) -> Result<FaultAssessment, RobustError> {
    if scenarios.is_empty() {
        return Err(RobustError::EmptyScenarioSet);
    }
    let zero = rational(0, 1)?;
    let one = rational(1, 1)?;
    let mut families = Vec::new();
    let mut worst = zero;
    let mut expected = zero;
    let mut prior_sum = zero;

    for evaluation in scenarios {
        if evaluation.cost.checked_cmp(zero)? == Ordering::Less {
            return Err(RobustError::NegativeCost);
        }
        if evaluation.scenario.recoverable && !evaluation.utility_satisfied {
            return Err(RobustError::RecoverableUtilityViolation {
                family_id: evaluation.scenario.public_fault_trace.family_id,
            });
        }
        let family = evaluation.scenario.public_fault_trace.family_id;
        if !families.contains(&family) {
            families.push(family);
        }
        if evaluation.cost.checked_cmp(worst)? == Ordering::Greater {
            worst = evaluation.cost;
        }
        if objective == CostObjective::ExpectedUnderExplicitPublicPrior {
            let prior = evaluation
                .public_prior
                .ok_or(RobustError::MissingPublicPrior)?;
            if prior.checked_cmp(zero)? == Ordering::Less {
                return Err(RobustError::NegativePublicPrior);
            }
            prior_sum = prior_sum.checked_add(prior)?;
            expected = expected.checked_add(prior.checked_mul(evaluation.cost)?)?;
        }
    }

    if families.len() < minimum_fault_families {
        return Err(RobustError::InsufficientFaultFamilies {
            required: minimum_fault_families,
            actual: families.len(),
        });
    }
    if objective == CostObjective::ExpectedUnderExplicitPublicPrior && prior_sum != one {
        return Err(RobustError::PublicPriorNotNormalized);
    }

    Ok(FaultAssessment {
        objective_value: match objective {
            CostObjective::WorstCase => worst,
            CostObjective::ExpectedUnderExplicitPublicPrior => expected,
        },
        worst_case_cost: worst,
        fault_family_count: families.len(),
    })
}

pub fn select_robust_optimum(
    candidates: &[MechanismEvaluation],
    objective: CostObjective,
    minimum_fault_families: usize,
) -> Result<RobustOptimum, RobustError> {
    if candidates.is_empty() {
        return Err(RobustError::EmptyCandidateSet);
    }
    let mut best: Option<RobustOptimum> = None;
    for candidate in candidates {
        let assessment =
            match assess_faults(&candidate.scenarios, objective, minimum_fault_families) {
                Ok(value) => value,
                Err(RobustError::RecoverableUtilityViolation { .. }) => continue,
                Err(error) => return Err(error),
            };
        let replace = match &best {
            None => true,
            Some(current) => {
                assessment
                    .objective_value
                    .checked_cmp(current.assessment.objective_value)?
                    == Ordering::Less
            }
        };
        if replace {
            best = Some(RobustOptimum {
                mechanism_id: candidate.mechanism_id,
                assessment,
            });
        }
    }
    best.ok_or(RobustError::NoRobustCandidate)
}

pub fn assess_collusion(
    left: &JointDistribution,
    right: &JointDistribution,
    randomness_mode: RandomnessMode,
    minimum_services: usize,
) -> Result<CollusionAssessment, RobustError> {
    let service_count = validate_joint_distribution(left)?;
    if validate_joint_distribution(right)? != service_count {
        return Err(RobustError::InconsistentServiceCount);
    }
    if service_count < minimum_services {
        return Err(RobustError::InsufficientServices {
            required: minimum_services,
            actual: service_count,
        });
    }

    let joint_left = left
        .outcomes
        .iter()
        .map(|mass| (mass.trace.services.clone(), mass.probability))
        .collect::<Vec<_>>();
    let joint_right = right
        .outcomes
        .iter()
        .map(|mass| (mass.trace.services.clone(), mass.probability))
        .collect::<Vec<_>>();
    let joint_tv = total_variation(&joint_left, &joint_right)?;

    let mut marginal_tvs = Vec::with_capacity(service_count);
    let mut maximum_marginal = rational(0, 1)?;
    for service in 0..service_count {
        let left_marginal = marginalize(left, service)?;
        let right_marginal = marginalize(right, service)?;
        let tv = total_variation(&left_marginal, &right_marginal)?;
        if tv.checked_cmp(maximum_marginal)? == Ordering::Greater {
            maximum_marginal = tv;
        }
        marginal_tvs.push(tv);
    }
    let leakage = nonnegative_difference(joint_tv, maximum_marginal)?;

    Ok(CollusionAssessment {
        randomness_mode,
        service_count,
        marginal_total_variation: marginal_tvs,
        maximum_marginal_total_variation: maximum_marginal,
        joint_total_variation: joint_tv,
        correlation_leakage: leakage,
        marginal_certificate_is_collusion_safe: joint_tv == maximum_marginal,
    })
}

fn validate_joint_distribution(distribution: &JointDistribution) -> Result<usize, RobustError> {
    if distribution.outcomes.is_empty() {
        return Err(RobustError::EmptyDistribution);
    }
    let zero = rational(0, 1)?;
    let one = rational(1, 1)?;
    let service_count = distribution.outcomes[0].trace.services.len();
    if service_count == 0 {
        return Err(RobustError::EmptyServiceSet);
    }
    let mut sum = zero;
    let mut previous: Option<&JointServiceTrace> = None;
    for mass in &distribution.outcomes {
        if mass.trace.services.len() != service_count {
            return Err(RobustError::InconsistentServiceCount);
        }
        if let Some(prior) = previous {
            if prior >= &mass.trace {
                return Err(RobustError::NonCanonicalOutcomeOrder);
            }
        }
        if mass.probability.checked_cmp(zero)? == Ordering::Less {
            return Err(RobustError::NegativeProbability);
        }
        sum = sum.checked_add(mass.probability)?;
        previous = Some(&mass.trace);
    }
    if sum != one {
        return Err(RobustError::DistributionNotNormalized);
    }
    Ok(service_count)
}

fn marginalize(
    distribution: &JointDistribution,
    service: usize,
) -> Result<Vec<(Vec<u32>, Rational)>, RobustError> {
    let mut marginal: Vec<(Vec<u32>, Rational)> = Vec::new();
    for mass in &distribution.outcomes {
        let trace = mass.trace.services[service].clone();
        if let Some((_, probability)) = marginal.iter_mut().find(|(key, _)| *key == trace) {
            *probability = probability.checked_add(mass.probability)?;
        } else {
            marginal.push((trace, mass.probability));
        }
    }
    marginal.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(marginal)
}

fn total_variation<T: Ord>(
    left: &[(T, Rational)],
    right: &[(T, Rational)],
) -> Result<Rational, RobustError> {
    let zero = rational(0, 1)?;
    let mut sum = zero;
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.len() || right_index < right.len() {
        let (left_probability, right_probability) =
            match (left.get(left_index), right.get(right_index)) {
                (Some(left_mass), Some(right_mass)) => match left_mass.0.cmp(&right_mass.0) {
                    Ordering::Less => {
                        left_index += 1;
                        (left_mass.1, zero)
                    }
                    Ordering::Greater => {
                        right_index += 1;
                        (zero, right_mass.1)
                    }
                    Ordering::Equal => {
                        left_index += 1;
                        right_index += 1;
                        (left_mass.1, right_mass.1)
                    }
                },
                (Some(left_mass), None) => {
                    left_index += 1;
                    (left_mass.1, zero)
                }
                (None, Some(right_mass)) => {
                    right_index += 1;
                    (zero, right_mass.1)
                }
                (None, None) => break,
            };
        sum = sum.checked_add(absolute_difference(left_probability, right_probability)?)?;
    }
    Ok(sum.checked_mul(rational(1, 2)?)?)
}

fn absolute_difference(left: Rational, right: Rational) -> Result<Rational, RobustError> {
    match left.checked_cmp(right)? {
        Ordering::Less => Ok(right.checked_add(left.checked_neg()?)?),
        _ => Ok(left.checked_add(right.checked_neg()?)?),
    }
}

fn nonnegative_difference(left: Rational, right: Rational) -> Result<Rational, RobustError> {
    if left.checked_cmp(right)? == Ordering::Less {
        return Ok(rational(0, 1)?);
    }
    Ok(left.checked_add(right.checked_neg()?)?)
}

fn rational(numerator: i128, denominator: i128) -> Result<Rational, RobustError> {
    Ok(Rational::new(numerator, denominator)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn r(numerator: i128, denominator: i128) -> Rational {
        Rational::new(numerator, denominator).expect("valid rational")
    }

    fn scenario(
        family: u32,
        utility: bool,
        cost: i128,
        prior: Option<Rational>,
    ) -> ScenarioEvaluation {
        ScenarioEvaluation {
            scenario: FaultScenario {
                public_fault_trace: FaultTrace {
                    family_id: family,
                    public_events: vec![family],
                },
                recoverable: true,
            },
            utility_satisfied: utility,
            cost: r(cost, 1),
            public_prior: prior,
        }
    }

    #[test]
    fn separates_worst_case_from_explicit_prior_expectation() {
        let scenarios = vec![
            scenario(1, true, 1, Some(r(1, 4))),
            scenario(2, true, 2, Some(r(1, 4))),
            scenario(3, true, 3, Some(r(1, 4))),
            scenario(4, true, 4, Some(r(1, 4))),
        ];
        let worst = assess_faults(&scenarios, CostObjective::WorstCase, 4).unwrap();
        let expected = assess_faults(
            &scenarios,
            CostObjective::ExpectedUnderExplicitPublicPrior,
            4,
        )
        .unwrap();
        assert_eq!(worst.objective_value, r(4, 1));
        assert_eq!(expected.objective_value, r(5, 2));
        assert_eq!(expected.worst_case_cost, r(4, 1));
    }

    #[test]
    fn rejects_implicit_prior_and_recoverable_failure() {
        let missing = vec![
            scenario(1, true, 1, None),
            scenario(2, true, 1, None),
            scenario(3, true, 1, None),
            scenario(4, true, 1, None),
        ];
        assert_eq!(
            assess_faults(&missing, CostObjective::ExpectedUnderExplicitPublicPrior, 4),
            Err(RobustError::MissingPublicPrior)
        );
        let mut failed = missing;
        failed[2].utility_satisfied = false;
        assert_eq!(
            assess_faults(&failed, CostObjective::WorstCase, 4),
            Err(RobustError::RecoverableUtilityViolation { family_id: 3 })
        );
    }

    #[test]
    fn selects_only_robust_candidate() {
        let mut invalid = vec![
            scenario(1, true, 1, None),
            scenario(2, false, 1, None),
            scenario(3, true, 1, None),
            scenario(4, true, 1, None),
        ];
        let valid = vec![
            scenario(1, true, 2, None),
            scenario(2, true, 2, None),
            scenario(3, true, 2, None),
            scenario(4, true, 2, None),
        ];
        invalid[0].cost = r(0, 1);
        let optimum = select_robust_optimum(
            &[
                MechanismEvaluation {
                    mechanism_id: 10,
                    scenarios: invalid,
                },
                MechanismEvaluation {
                    mechanism_id: 20,
                    scenarios: valid,
                },
            ],
            CostObjective::WorstCase,
            FROZEN_FAULT_FAMILY_GATE,
        )
        .unwrap();
        assert_eq!(optimum.mechanism_id, 20);
    }

    fn joint(outcomes: &[(&[&[u32]], Rational)]) -> JointDistribution {
        JointDistribution {
            outcomes: outcomes
                .iter()
                .map(|(services, probability)| JointMass {
                    trace: JointServiceTrace {
                        services: services.iter().map(|trace| trace.to_vec()).collect(),
                    },
                    probability: *probability,
                })
                .collect(),
        }
    }

    #[test]
    fn joint_model_detects_leakage_hidden_from_all_marginals() {
        let left = joint(&[
            (&[&[0], &[0], &[0], &[0]], r(1, 2)),
            (&[&[1], &[1], &[0], &[0]], r(1, 2)),
        ]);
        let right = joint(&[
            (&[&[0], &[1], &[0], &[0]], r(1, 2)),
            (&[&[1], &[0], &[0], &[0]], r(1, 2)),
        ]);
        let assessment = assess_collusion(
            &left,
            &right,
            RandomnessMode::Correlated,
            FROZEN_COLLUSION_SERVICE_GATE,
        )
        .unwrap();
        assert_eq!(assessment.maximum_marginal_total_variation, r(0, 1));
        assert_eq!(assessment.joint_total_variation, r(1, 1));
        assert_eq!(assessment.correlation_leakage, r(1, 1));
        assert!(!assessment.marginal_certificate_is_collusion_safe);
    }

    #[test]
    fn enforces_four_service_collusion_gate() {
        let distribution = joint(&[(&[&[0], &[0], &[0]], r(1, 1))]);
        assert_eq!(
            assess_collusion(
                &distribution,
                &distribution,
                RandomnessMode::Independent,
                FROZEN_COLLUSION_SERVICE_GATE,
            ),
            Err(RobustError::InsufficientServices {
                required: 4,
                actual: 3
            })
        );
    }
}
