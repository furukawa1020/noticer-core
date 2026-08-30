use crate::{
    HardwareStatus, MetricAggregate, MetricGroupKey, MetricStatisticsStatus, StatisticsArtifact,
    StatisticsError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const GATE_PLAN_SCHEMA: &str = "quotient-seal.performance-budget-plan.v1";
pub const GATE_ARTIFACT_SCHEMA: &str = "quotient-seal.performance-gate.v1";

const PLAN_DOMAIN: &[u8] = b"QUOTIENT_SEAL_PERFORMANCE_BUDGET_PLAN_V1";
const ARTIFACT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_PERFORMANCE_GATE_V1";
const SCALE_MILLION: u128 = 1_000_000;
const HARD_MAX_RULES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetStatistic {
    Median,
    P95,
    P99,
    MedianAbsoluteDeviation,
    FailureRateMillionths,
    InconclusiveRateMillionths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "constraint", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetConstraint {
    AbsoluteMaximum { limit: u64 },
    AbsoluteIncreaseMaximum { limit: u64 },
    RelativeMaximum { ratio_millionths: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetRule {
    pub rule_id: u32,
    pub key: MetricGroupKey,
    pub statistic: BudgetStatistic,
    pub constraint: BudgetConstraint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetPlan {
    pub schema: String,
    pub rules: Vec<BudgetRule>,
    pub artifact_sha256: [u8; 32],
}

impl BudgetPlan {
    pub fn build(mut rules: Vec<BudgetRule>) -> Result<Self, PerformanceGateError> {
        if rules.is_empty() || rules.len() > HARD_MAX_RULES {
            return Err(PerformanceGateError::InvalidPlan);
        }
        rules.sort_by_key(|rule| rule.rule_id);
        if rules
            .windows(2)
            .any(|pair| pair[0].rule_id == pair[1].rule_id)
        {
            return Err(PerformanceGateError::DuplicateRule);
        }
        let mut selectors = BTreeSet::new();
        for rule in &rules {
            if !selectors.insert((rule.key, statistic_code(rule.statistic))) {
                return Err(PerformanceGateError::DuplicateRule);
            }
            if let BudgetConstraint::RelativeMaximum { ratio_millionths } = rule.constraint {
                if ratio_millionths == 0 {
                    return Err(PerformanceGateError::InvalidPlan);
                }
            }
        }
        let mut plan = Self {
            schema: GATE_PLAN_SCHEMA.to_owned(),
            rules,
            artifact_sha256: [0; 32],
        };
        plan.artifact_sha256 = plan.recomputed_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), PerformanceGateError> {
        let expected = Self::build(self.rules.clone())?;
        if self != &expected {
            return Err(PerformanceGateError::ArtifactMismatch);
        }
        Ok(())
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], PerformanceGateError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| PerformanceGateError::Json)?;
        Ok(domain_hash(PLAN_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateInconclusiveReason {
    MissingCandidateGroup,
    MissingBaselineGroup,
    UnitMismatch,
    InsufficientSuccessSamples,
    ZeroBaseline,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateRuleOutcome {
    Pass,
    Fail,
    Inconclusive { reason: GateInconclusiveReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluation {
    pub rule_id: u32,
    pub outcome: GateRuleOutcome,
    pub candidate_value: Option<u64>,
    pub baseline_value: Option<u64>,
    pub observed_increase: Option<u64>,
    pub observed_ratio_millionths: Option<u64>,
    pub budget_plan_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PerformanceGateVerdict {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceGateArtifact {
    pub schema: String,
    pub plan: BudgetPlan,
    pub baseline: StatisticsArtifact,
    pub candidate: StatisticsArtifact,
    pub evaluations: Vec<GateEvaluation>,
    pub verdict: PerformanceGateVerdict,
    pub security_interpretation: String,
    pub evidence_origin: String,
    pub hardware_status: HardwareStatus,
    pub artifact_sha256: [u8; 32],
}

impl PerformanceGateArtifact {
    pub fn validate(&self) -> Result<(), PerformanceGateError> {
        self.plan.validate()?;
        self.baseline
            .validate()
            .map_err(PerformanceGateError::Statistics)?;
        self.candidate
            .validate()
            .map_err(PerformanceGateError::Statistics)?;
        let expected = compute_evaluations(&self.plan, &self.baseline, &self.candidate);
        if self.schema != GATE_ARTIFACT_SCHEMA
            || self.evaluations != expected
            || self.verdict != derive_verdict(&expected)
            || self.security_interpretation != "NOT_A_SECURITY_VERDICT"
            || self.evidence_origin != "PERFORMANCE_BUDGET_GATE"
            || self.hardware_status != HardwareStatus::NotVerified
            || self.artifact_sha256 != self.recomputed_sha256()?
        {
            return Err(PerformanceGateError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, PerformanceGateError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| PerformanceGateError::Json)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], PerformanceGateError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| PerformanceGateError::Json)?;
        Ok(domain_hash(ARTIFACT_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PerformanceGateError {
    #[error("performance budget plan is invalid")]
    InvalidPlan,
    #[error("performance budget rule is duplicated")]
    DuplicateRule,
    #[error("performance gate artifact failed full recomputation")]
    ArtifactMismatch,
    #[error("performance gate JSON serialization failed")]
    Json,
    #[error("statistics artifact is invalid: {0}")]
    Statistics(StatisticsError),
}

pub fn evaluate_budget(
    plan: BudgetPlan,
    baseline: StatisticsArtifact,
    candidate: StatisticsArtifact,
) -> Result<PerformanceGateArtifact, PerformanceGateError> {
    plan.validate()?;
    baseline
        .validate()
        .map_err(PerformanceGateError::Statistics)?;
    candidate
        .validate()
        .map_err(PerformanceGateError::Statistics)?;
    let evaluations = compute_evaluations(&plan, &baseline, &candidate);
    let verdict = derive_verdict(&evaluations);
    let mut artifact = PerformanceGateArtifact {
        schema: GATE_ARTIFACT_SCHEMA.to_owned(),
        plan,
        baseline,
        candidate,
        evaluations,
        verdict,
        security_interpretation: "NOT_A_SECURITY_VERDICT".to_owned(),
        evidence_origin: "PERFORMANCE_BUDGET_GATE".to_owned(),
        hardware_status: HardwareStatus::NotVerified,
        artifact_sha256: [0; 32],
    };
    artifact.artifact_sha256 = artifact.recomputed_sha256()?;
    artifact.validate()?;
    Ok(artifact)
}

fn compute_evaluations(
    plan: &BudgetPlan,
    baseline: &StatisticsArtifact,
    candidate: &StatisticsArtifact,
) -> Vec<GateEvaluation> {
    plan.rules
        .iter()
        .map(|rule| evaluate_rule(*rule, plan.artifact_sha256, baseline, candidate))
        .collect()
}

fn evaluate_rule(
    rule: BudgetRule,
    plan_sha256: [u8; 32],
    baseline: &StatisticsArtifact,
    candidate: &StatisticsArtifact,
) -> GateEvaluation {
    let candidate_value = match extract_value(candidate, rule.key, rule.statistic, true) {
        Ok(value) => value,
        Err(reason) => return inconclusive(rule.rule_id, plan_sha256, reason),
    };
    match rule.constraint {
        BudgetConstraint::AbsoluteMaximum { limit } => GateEvaluation {
            rule_id: rule.rule_id,
            outcome: if candidate_value <= limit {
                GateRuleOutcome::Pass
            } else {
                GateRuleOutcome::Fail
            },
            candidate_value: Some(candidate_value),
            baseline_value: None,
            observed_increase: None,
            observed_ratio_millionths: None,
            budget_plan_sha256: plan_sha256,
        },
        BudgetConstraint::AbsoluteIncreaseMaximum { limit } => {
            let baseline_value = match extract_value(baseline, rule.key, rule.statistic, false) {
                Ok(value) => value,
                Err(reason) => return inconclusive(rule.rule_id, plan_sha256, reason),
            };
            let increase = candidate_value.saturating_sub(baseline_value);
            GateEvaluation {
                rule_id: rule.rule_id,
                outcome: if increase <= limit {
                    GateRuleOutcome::Pass
                } else {
                    GateRuleOutcome::Fail
                },
                candidate_value: Some(candidate_value),
                baseline_value: Some(baseline_value),
                observed_increase: Some(increase),
                observed_ratio_millionths: None,
                budget_plan_sha256: plan_sha256,
            }
        }
        BudgetConstraint::RelativeMaximum { ratio_millionths } => {
            let baseline_value = match extract_value(baseline, rule.key, rule.statistic, false) {
                Ok(value) => value,
                Err(reason) => return inconclusive(rule.rule_id, plan_sha256, reason),
            };
            if baseline_value == 0 && candidate_value != 0 {
                return GateEvaluation {
                    rule_id: rule.rule_id,
                    outcome: GateRuleOutcome::Inconclusive {
                        reason: GateInconclusiveReason::ZeroBaseline,
                    },
                    candidate_value: Some(candidate_value),
                    baseline_value: Some(0),
                    observed_increase: Some(candidate_value),
                    observed_ratio_millionths: None,
                    budget_plan_sha256: plan_sha256,
                };
            }
            let ratio = if baseline_value == 0 {
                1_000_000
            } else {
                let numerator = u128::from(candidate_value) * SCALE_MILLION;
                let rounded =
                    (numerator + u128::from(baseline_value) / 2) / u128::from(baseline_value);
                let Ok(ratio) = u64::try_from(rounded) else {
                    return inconclusive(
                        rule.rule_id,
                        plan_sha256,
                        GateInconclusiveReason::ArithmeticOverflow,
                    );
                };
                ratio
            };
            GateEvaluation {
                rule_id: rule.rule_id,
                outcome: if ratio <= ratio_millionths {
                    GateRuleOutcome::Pass
                } else {
                    GateRuleOutcome::Fail
                },
                candidate_value: Some(candidate_value),
                baseline_value: Some(baseline_value),
                observed_increase: Some(candidate_value.saturating_sub(baseline_value)),
                observed_ratio_millionths: Some(ratio),
                budget_plan_sha256: plan_sha256,
            }
        }
    }
}

fn extract_value(
    artifact: &StatisticsArtifact,
    key: MetricGroupKey,
    statistic: BudgetStatistic,
    candidate: bool,
) -> Result<u64, GateInconclusiveReason> {
    let Some(group) = artifact.groups.iter().find(|group| group.key == key) else {
        let same_dimension = artifact.groups.iter().any(|group| {
            group.key.stage == key.stage
                && group.key.metric == key.metric
                && group.key.case == key.case
                && group.key.provenance == key.provenance
                && group.key.unit != key.unit
        });
        return Err(if same_dimension {
            GateInconclusiveReason::UnitMismatch
        } else if candidate {
            GateInconclusiveReason::MissingCandidateGroup
        } else {
            GateInconclusiveReason::MissingBaselineGroup
        });
    };
    match statistic {
        BudgetStatistic::FailureRateMillionths => rate_millionths(group.counts.failure, group),
        BudgetStatistic::InconclusiveRateMillionths => {
            rate_millionths(group.counts.inconclusive, group)
        }
        BudgetStatistic::Median
        | BudgetStatistic::P95
        | BudgetStatistic::P99
        | BudgetStatistic::MedianAbsoluteDeviation => match group.statistics {
            MetricStatisticsStatus::Ready {
                median,
                p95,
                p99,
                median_absolute_deviation,
            } => Ok(match statistic {
                BudgetStatistic::Median => median,
                BudgetStatistic::P95 => p95,
                BudgetStatistic::P99 => p99,
                BudgetStatistic::MedianAbsoluteDeviation => median_absolute_deviation,
                BudgetStatistic::FailureRateMillionths
                | BudgetStatistic::InconclusiveRateMillionths => unreachable!(),
            }),
            MetricStatisticsStatus::Inconclusive { .. } => {
                Err(GateInconclusiveReason::InsufficientSuccessSamples)
            }
        },
    }
}

fn rate_millionths(count: u32, group: &MetricAggregate) -> Result<u64, GateInconclusiveReason> {
    if group.counts.total == 0 {
        return Err(GateInconclusiveReason::InsufficientSuccessSamples);
    }
    let numerator = u128::from(count) * SCALE_MILLION;
    Ok(((numerator + u128::from(group.counts.total) / 2) / u128::from(group.counts.total)) as u64)
}

fn inconclusive(
    rule_id: u32,
    plan_sha256: [u8; 32],
    reason: GateInconclusiveReason,
) -> GateEvaluation {
    GateEvaluation {
        rule_id,
        outcome: GateRuleOutcome::Inconclusive { reason },
        candidate_value: None,
        baseline_value: None,
        observed_increase: None,
        observed_ratio_millionths: None,
        budget_plan_sha256: plan_sha256,
    }
}

fn derive_verdict(evaluations: &[GateEvaluation]) -> PerformanceGateVerdict {
    if evaluations
        .iter()
        .any(|evaluation| evaluation.outcome == GateRuleOutcome::Fail)
    {
        PerformanceGateVerdict::Fail
    } else if evaluations
        .iter()
        .any(|evaluation| matches!(evaluation.outcome, GateRuleOutcome::Inconclusive { .. }))
    {
        PerformanceGateVerdict::Inconclusive
    } else {
        PerformanceGateVerdict::Pass
    }
}

const fn statistic_code(statistic: BudgetStatistic) -> u8 {
    match statistic {
        BudgetStatistic::Median => 0,
        BudgetStatistic::P95 => 1,
        BudgetStatistic::P99 => 2,
        BudgetStatistic::MedianAbsoluteDeviation => 3,
        BudgetStatistic::FailureRateMillionths => 4,
        BudgetStatistic::InconclusiveRateMillionths => 5,
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
