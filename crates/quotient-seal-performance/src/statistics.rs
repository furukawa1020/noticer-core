use crate::{
    BenchmarkCase, HardwareStatus, MeasurementCampaign, MeasurementContractError,
    MeasurementFailureReason, MeasurementInconclusiveReason, MeasurementMetric, MeasurementOutcome,
    MeasurementProvenance, MeasurementStage, MeasurementUnit,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const STATISTICS_PLAN_SCHEMA: &str = "quotient-seal.statistics-plan.v1";
pub const STATISTICS_ARTIFACT_SCHEMA: &str = "quotient-seal.statistics-artifact.v1";

const PLAN_DOMAIN: &[u8] = b"QUOTIENT_SEAL_STATISTICS_PLAN_V1";
const ARTIFACT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_STATISTICS_ARTIFACT_V1";
const SCALE_MILLION: u128 = 1_000_000;
const HARD_MAX_CAMPAIGNS: u32 = 100_000;
const HARD_MAX_SAMPLES: u32 = 100_000_000;
const HARD_MAX_COMPARISONS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackClass {
    Negative,
    Positive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttackLabelBinding {
    pub module_family_alias: u32,
    pub class: AttackClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EffectSizePair {
    pub stage: MeasurementStage,
    pub metric: MeasurementMetric,
    pub provenance: MeasurementProvenance,
    pub baseline_case: BenchmarkCase,
    pub candidate_case: BenchmarkCase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticsPlan {
    pub schema: String,
    pub min_success_samples: u32,
    pub max_campaigns: u32,
    pub max_total_samples: u32,
    pub effect_size_pairs: Vec<EffectSizePair>,
    pub attack_labels: Vec<AttackLabelBinding>,
    pub artifact_sha256: [u8; 32],
}

impl StatisticsPlan {
    pub fn build(
        min_success_samples: u32,
        max_campaigns: u32,
        max_total_samples: u32,
        mut effect_size_pairs: Vec<EffectSizePair>,
        mut attack_labels: Vec<AttackLabelBinding>,
    ) -> Result<Self, StatisticsError> {
        if min_success_samples == 0
            || max_campaigns == 0
            || max_campaigns > HARD_MAX_CAMPAIGNS
            || max_total_samples == 0
            || max_total_samples > HARD_MAX_SAMPLES
            || effect_size_pairs.len() > HARD_MAX_COMPARISONS
            || attack_labels.len() > HARD_MAX_COMPARISONS
        {
            return Err(StatisticsError::InvalidPlan);
        }
        for pair in &effect_size_pairs {
            if pair.baseline_case == pair.candidate_case
                || pair.metric == MeasurementMetric::AttackScore
            {
                return Err(StatisticsError::InvalidPlan);
            }
        }
        effect_size_pairs.sort_unstable();
        if effect_size_pairs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StatisticsError::DuplicatePlanEntry);
        }
        attack_labels.sort_unstable();
        if attack_labels
            .windows(2)
            .any(|pair| pair[0].module_family_alias == pair[1].module_family_alias)
        {
            return Err(StatisticsError::DuplicatePlanEntry);
        }
        let mut plan = Self {
            schema: STATISTICS_PLAN_SCHEMA.to_owned(),
            min_success_samples,
            max_campaigns,
            max_total_samples,
            effect_size_pairs,
            attack_labels,
            artifact_sha256: [0; 32],
        };
        plan.artifact_sha256 = plan.recomputed_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), StatisticsError> {
        let expected = Self::build(
            self.min_success_samples,
            self.max_campaigns,
            self.max_total_samples,
            self.effect_size_pairs.clone(),
            self.attack_labels.clone(),
        )?;
        if self != &expected {
            return Err(StatisticsError::ArtifactMismatch);
        }
        Ok(())
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], StatisticsError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| StatisticsError::Json)?;
        Ok(domain_hash(PLAN_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MetricGroupKey {
    pub stage: MeasurementStage,
    pub metric: MeasurementMetric,
    pub unit: MeasurementUnit,
    pub case: BenchmarkCase,
    pub provenance: MeasurementProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureReasonCount {
    pub reason: MeasurementFailureReason,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InconclusiveReasonCount {
    pub reason: MeasurementInconclusiveReason,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensoredCounts {
    pub total: u32,
    pub success: u32,
    pub failure: u32,
    pub inconclusive: u32,
    pub failure_reasons: Vec<FailureReasonCount>,
    pub inconclusive_reasons: Vec<InconclusiveReasonCount>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatisticsInconclusiveReason {
    InsufficientSuccessSamples,
    MissingGroup,
    MissingAttackLabel,
    SingleAttackClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetricStatisticsStatus {
    Ready {
        median: u64,
        p95: u64,
        p99: u64,
        median_absolute_deviation: u64,
    },
    Inconclusive {
        reason: StatisticsInconclusiveReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricAggregate {
    pub key: MetricGroupKey,
    pub counts: CensoredCounts,
    pub statistics: MetricStatisticsStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectSizeStatus {
    Ready {
        cliffs_delta_millionths: i64,
    },
    Inconclusive {
        reason: StatisticsInconclusiveReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSizeAggregate {
    pub pair: EffectSizePair,
    pub baseline_success: u32,
    pub candidate_success: u32,
    pub status: EffectSizeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttackAucKey {
    pub compiler_config_alias: u32,
    pub engine_alias: u32,
    pub provenance: MeasurementProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackAucStatus {
    Ready {
        auc_millionths: u64,
    },
    Inconclusive {
        reason: StatisticsInconclusiveReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackAucAggregate {
    pub key: AttackAucKey,
    pub positive_success: u32,
    pub negative_success: u32,
    pub failure: u32,
    pub inconclusive: u32,
    pub status: AttackAucStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticsArtifact {
    pub schema: String,
    pub plan: StatisticsPlan,
    pub source_campaign_sha256: Vec<[u8; 32]>,
    pub groups: Vec<MetricAggregate>,
    pub effect_sizes: Vec<EffectSizeAggregate>,
    pub attack_auc: Vec<AttackAucAggregate>,
    pub evidence_origin: String,
    pub hardware_status: HardwareStatus,
    pub artifact_sha256: [u8; 32],
}

impl StatisticsArtifact {
    pub fn validate(&self) -> Result<(), StatisticsError> {
        self.plan.validate()?;
        if self.schema != STATISTICS_ARTIFACT_SCHEMA
            || self.source_campaign_sha256.is_empty()
            || self
                .source_campaign_sha256
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.source_campaign_sha256.contains(&[0; 32])
            || self
                .groups
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || self.effect_sizes.len() != self.plan.effect_size_pairs.len()
            || self
                .effect_sizes
                .iter()
                .zip(&self.plan.effect_size_pairs)
                .any(|(aggregate, pair)| aggregate.pair != *pair)
            || self
                .attack_auc
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || self.evidence_origin != "TYPED_MEASUREMENT_AGGREGATE"
            || self.hardware_status != HardwareStatus::NotVerified
        {
            return Err(StatisticsError::ArtifactMismatch);
        }
        for group in &self.groups {
            validate_counts(&group.counts)?;
            if let MetricStatisticsStatus::Ready {
                median, p95, p99, ..
            } = group.statistics
            {
                if group.counts.success < self.plan.min_success_samples || median > p95 || p95 > p99
                {
                    return Err(StatisticsError::ArtifactMismatch);
                }
            }
        }
        if self.effect_sizes.iter().any(|aggregate| {
            matches!(
                aggregate.status,
                EffectSizeStatus::Ready {
                    cliffs_delta_millionths
                } if !(-1_000_000..=1_000_000).contains(&cliffs_delta_millionths)
            )
        }) || self.attack_auc.iter().any(|aggregate| {
            matches!(
                aggregate.status,
                AttackAucStatus::Ready { auc_millionths } if auc_millionths > 1_000_000
            )
        }) {
            return Err(StatisticsError::ArtifactMismatch);
        }
        if self.artifact_sha256 != self.recomputed_sha256()? {
            return Err(StatisticsError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, StatisticsError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| StatisticsError::Json)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], StatisticsError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| StatisticsError::Json)?;
        Ok(domain_hash(ARTIFACT_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StatisticsError {
    #[error("statistics plan is invalid")]
    InvalidPlan,
    #[error("statistics plan entry is duplicated")]
    DuplicatePlanEntry,
    #[error("statistics campaign or sample bound was reached")]
    InputBound,
    #[error("statistics source campaign is duplicated")]
    DuplicateCampaign,
    #[error("statistics artifact failed full recomputation")]
    ArtifactMismatch,
    #[error("statistics JSON serialization failed")]
    Json,
    #[error("measurement campaign is invalid: {0}")]
    Campaign(MeasurementContractError),
}

pub fn aggregate_campaigns(
    plan: StatisticsPlan,
    campaigns: &[MeasurementCampaign],
) -> Result<StatisticsArtifact, StatisticsError> {
    plan.validate()?;
    if campaigns.is_empty() || campaigns.len() > plan.max_campaigns as usize {
        return Err(StatisticsError::InputBound);
    }
    let mut sources = Vec::with_capacity(campaigns.len());
    let mut seen_samples = BTreeSet::new();
    let mut total_samples = 0_u64;
    let mut grouped = BTreeMap::<MetricGroupKey, Vec<&crate::MeasurementSample>>::new();
    for campaign in campaigns {
        campaign.validate().map_err(StatisticsError::Campaign)?;
        sources.push(campaign.artifact_sha256);
        total_samples = total_samples
            .checked_add(campaign.samples.len() as u64)
            .ok_or(StatisticsError::InputBound)?;
        for sample in &campaign.samples {
            if !seen_samples.insert(sample.sample_sha256) {
                return Err(StatisticsError::DuplicateCampaign);
            }
            let key = MetricGroupKey {
                stage: sample.stage,
                metric: sample.metric,
                unit: sample.unit,
                case: sample.case,
                provenance: sample.provenance,
            };
            grouped.entry(key).or_default().push(sample);
        }
    }
    if total_samples > u64::from(plan.max_total_samples) {
        return Err(StatisticsError::InputBound);
    }
    sources.sort_unstable();
    if sources.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StatisticsError::DuplicateCampaign);
    }

    let mut success_values = BTreeMap::new();
    let mut groups = Vec::with_capacity(grouped.len());
    for (key, samples) in grouped {
        let mut values = successful_values(&samples);
        values.sort_unstable();
        let counts = censored_counts(&samples)?;
        let statistics = if values.len() < plan.min_success_samples as usize {
            MetricStatisticsStatus::Inconclusive {
                reason: StatisticsInconclusiveReason::InsufficientSuccessSamples,
            }
        } else {
            let median = nearest_rank(&values, 50);
            let mut deviations: Vec<_> =
                values.iter().map(|value| value.abs_diff(median)).collect();
            deviations.sort_unstable();
            MetricStatisticsStatus::Ready {
                median,
                p95: nearest_rank(&values, 95),
                p99: nearest_rank(&values, 99),
                median_absolute_deviation: nearest_rank(&deviations, 50),
            }
        };
        success_values.insert(key, values);
        groups.push(MetricAggregate {
            key,
            counts,
            statistics,
        });
    }
    let effect_sizes = plan
        .effect_size_pairs
        .iter()
        .copied()
        .map(|pair| effect_size(pair, &success_values, plan.min_success_samples))
        .collect();
    let attack_auc = attack_auc(&plan, campaigns)?;
    let mut artifact = StatisticsArtifact {
        schema: STATISTICS_ARTIFACT_SCHEMA.to_owned(),
        plan,
        source_campaign_sha256: sources,
        groups,
        effect_sizes,
        attack_auc,
        evidence_origin: "TYPED_MEASUREMENT_AGGREGATE".to_owned(),
        hardware_status: HardwareStatus::NotVerified,
        artifact_sha256: [0; 32],
    };
    artifact.artifact_sha256 = artifact.recomputed_sha256()?;
    artifact.validate()?;
    Ok(artifact)
}

fn effect_size(
    pair: EffectSizePair,
    values: &BTreeMap<MetricGroupKey, Vec<u64>>,
    minimum: u32,
) -> EffectSizeAggregate {
    let baseline_key = MetricGroupKey {
        stage: pair.stage,
        metric: pair.metric,
        unit: pair.metric.expected_unit(),
        case: pair.baseline_case,
        provenance: pair.provenance,
    };
    let candidate_key = MetricGroupKey {
        case: pair.candidate_case,
        ..baseline_key
    };
    let baseline = values.get(&baseline_key);
    let candidate = values.get(&candidate_key);
    let baseline_success = baseline.map_or(0, |values| values.len() as u32);
    let candidate_success = candidate.map_or(0, |values| values.len() as u32);
    let status = match (baseline, candidate) {
        (Some(_), Some(_)) if baseline_success < minimum || candidate_success < minimum => {
            EffectSizeStatus::Inconclusive {
                reason: StatisticsInconclusiveReason::InsufficientSuccessSamples,
            }
        }
        (Some(baseline), Some(candidate)) => EffectSizeStatus::Ready {
            cliffs_delta_millionths: cliffs_delta(baseline, candidate),
        },
        _ => EffectSizeStatus::Inconclusive {
            reason: StatisticsInconclusiveReason::MissingGroup,
        },
    };
    EffectSizeAggregate {
        pair,
        baseline_success,
        candidate_success,
        status,
    }
}

fn cliffs_delta(baseline: &[u64], candidate: &[u64]) -> i64 {
    let mut greater = 0_u128;
    let mut less = 0_u128;
    for candidate_value in candidate {
        for baseline_value in baseline {
            if candidate_value > baseline_value {
                greater += 1;
            } else if candidate_value < baseline_value {
                less += 1;
            }
        }
    }
    let pairs = baseline.len() as u128 * candidate.len() as u128;
    let difference = greater.abs_diff(less);
    let magnitude = ((difference * SCALE_MILLION) + pairs / 2) / pairs;
    if greater >= less {
        magnitude as i64
    } else {
        -(magnitude as i64)
    }
}

fn attack_auc(
    plan: &StatisticsPlan,
    campaigns: &[MeasurementCampaign],
) -> Result<Vec<AttackAucAggregate>, StatisticsError> {
    let labels: BTreeMap<_, _> = plan
        .attack_labels
        .iter()
        .map(|binding| (binding.module_family_alias, binding.class))
        .collect();
    let mut groups = BTreeMap::<AttackAucKey, AttackInputs>::new();
    for campaign in campaigns {
        for sample in &campaign.samples {
            if sample.stage != MeasurementStage::AttackEvaluation
                || sample.metric != MeasurementMetric::AttackScore
            {
                continue;
            }
            let key = AttackAucKey {
                compiler_config_alias: sample.case.compiler_config_alias,
                engine_alias: sample.case.engine_alias,
                provenance: sample.provenance,
            };
            let input = groups.entry(key).or_default();
            let label = labels.get(&sample.case.module_family_alias).copied();
            match sample.outcome {
                MeasurementOutcome::Success { value } => match label {
                    Some(AttackClass::Positive) => input.positive.push(value),
                    Some(AttackClass::Negative) => input.negative.push(value),
                    None => input.missing_label = true,
                },
                MeasurementOutcome::Failure { .. } => input.failure += 1,
                MeasurementOutcome::Inconclusive { .. } => input.inconclusive += 1,
            }
        }
    }
    Ok(groups
        .into_iter()
        .map(|(key, input)| {
            let status = if input.missing_label {
                AttackAucStatus::Inconclusive {
                    reason: StatisticsInconclusiveReason::MissingAttackLabel,
                }
            } else if input.positive.is_empty() || input.negative.is_empty() {
                AttackAucStatus::Inconclusive {
                    reason: StatisticsInconclusiveReason::SingleAttackClass,
                }
            } else {
                AttackAucStatus::Ready {
                    auc_millionths: auc_millionths(&input.positive, &input.negative),
                }
            };
            AttackAucAggregate {
                key,
                positive_success: input.positive.len() as u32,
                negative_success: input.negative.len() as u32,
                failure: input.failure,
                inconclusive: input.inconclusive,
                status,
            }
        })
        .collect())
}

#[derive(Default)]
struct AttackInputs {
    positive: Vec<u64>,
    negative: Vec<u64>,
    failure: u32,
    inconclusive: u32,
    missing_label: bool,
}

fn auc_millionths(positive: &[u64], negative: &[u64]) -> u64 {
    let mut twice_credit = 0_u128;
    for positive_score in positive {
        for negative_score in negative {
            if positive_score > negative_score {
                twice_credit += 2;
            } else if positive_score == negative_score {
                twice_credit += 1;
            }
        }
    }
    let denominator = 2_u128 * positive.len() as u128 * negative.len() as u128;
    (((twice_credit * SCALE_MILLION) + denominator / 2) / denominator) as u64
}

fn successful_values(samples: &[&crate::MeasurementSample]) -> Vec<u64> {
    samples
        .iter()
        .filter_map(|sample| match sample.outcome {
            MeasurementOutcome::Success { value } => Some(value),
            MeasurementOutcome::Failure { .. } | MeasurementOutcome::Inconclusive { .. } => None,
        })
        .collect()
}

fn censored_counts(
    samples: &[&crate::MeasurementSample],
) -> Result<CensoredCounts, StatisticsError> {
    let mut failure = [0_u32; 5];
    let mut inconclusive = [0_u32; 6];
    let mut success_count = 0_u32;
    for sample in samples {
        match sample.outcome {
            MeasurementOutcome::Success { .. } => success_count += 1,
            MeasurementOutcome::Failure { reason } => failure[failure_index(reason)] += 1,
            MeasurementOutcome::Inconclusive { reason } => {
                inconclusive[inconclusive_index(reason)] += 1;
            }
        }
    }
    let failure_count = failure.iter().sum();
    let inconclusive_count = inconclusive.iter().sum();
    let total = success_count
        .checked_add(failure_count)
        .and_then(|value| value.checked_add(inconclusive_count))
        .ok_or(StatisticsError::InputBound)?;
    Ok(CensoredCounts {
        total,
        success: success_count,
        failure: failure_count,
        inconclusive: inconclusive_count,
        failure_reasons: failure_histogram(failure),
        inconclusive_reasons: inconclusive_histogram(inconclusive),
    })
}

fn validate_counts(counts: &CensoredCounts) -> Result<(), StatisticsError> {
    let failure: u32 = counts.failure_reasons.iter().map(|entry| entry.count).sum();
    let inconclusive: u32 = counts
        .inconclusive_reasons
        .iter()
        .map(|entry| entry.count)
        .sum();
    let expected_total = counts
        .success
        .checked_add(counts.failure)
        .and_then(|value| value.checked_add(counts.inconclusive))
        .ok_or(StatisticsError::ArtifactMismatch)?;
    if counts.total != expected_total
        || failure != counts.failure
        || inconclusive != counts.inconclusive
        || counts.failure_reasons.iter().any(|entry| entry.count == 0)
        || counts
            .inconclusive_reasons
            .iter()
            .any(|entry| entry.count == 0)
    {
        return Err(StatisticsError::ArtifactMismatch);
    }
    Ok(())
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> u64 {
    let rank = (percentile * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

const fn failure_index(reason: MeasurementFailureReason) -> usize {
    match reason {
        MeasurementFailureReason::ToolError => 0,
        MeasurementFailureReason::ParseError => 1,
        MeasurementFailureReason::ValidationError => 2,
        MeasurementFailureReason::CheckerRejected => 3,
        MeasurementFailureReason::RuntimeTrap => 4,
    }
}

const fn inconclusive_index(reason: MeasurementInconclusiveReason) -> usize {
    match reason {
        MeasurementInconclusiveReason::Unsupported => 0,
        MeasurementInconclusiveReason::ResourceBound => 1,
        MeasurementInconclusiveReason::Timeout => 2,
        MeasurementInconclusiveReason::MissingMetadata => 3,
        MeasurementInconclusiveReason::CheckerDisagreement => 4,
        MeasurementInconclusiveReason::WallClockNotOptedIn => 5,
    }
}

fn failure_histogram(counts: [u32; 5]) -> Vec<FailureReasonCount> {
    [
        MeasurementFailureReason::ToolError,
        MeasurementFailureReason::ParseError,
        MeasurementFailureReason::ValidationError,
        MeasurementFailureReason::CheckerRejected,
        MeasurementFailureReason::RuntimeTrap,
    ]
    .into_iter()
    .zip(counts)
    .filter_map(|(reason, count)| (count > 0).then_some(FailureReasonCount { reason, count }))
    .collect()
}

fn inconclusive_histogram(counts: [u32; 6]) -> Vec<InconclusiveReasonCount> {
    [
        MeasurementInconclusiveReason::Unsupported,
        MeasurementInconclusiveReason::ResourceBound,
        MeasurementInconclusiveReason::Timeout,
        MeasurementInconclusiveReason::MissingMetadata,
        MeasurementInconclusiveReason::CheckerDisagreement,
        MeasurementInconclusiveReason::WallClockNotOptedIn,
    ]
    .into_iter()
    .zip(counts)
    .filter_map(|(reason, count)| (count > 0).then_some(InconclusiveReasonCount { reason, count }))
    .collect()
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
