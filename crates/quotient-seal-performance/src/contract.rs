use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const PERFORMANCE_SAMPLE_SCHEMA: &str = "quotient-seal.performance-sample.v1";
pub const PERFORMANCE_CAMPAIGN_SCHEMA: &str = "quotient-seal.performance-campaign.v1";

const SAMPLE_DOMAIN: &[u8] = b"QUOTIENT_SEAL_PERFORMANCE_SAMPLE_V1";
const CAMPAIGN_DOMAIN: &[u8] = b"QUOTIENT_SEAL_PERFORMANCE_CAMPAIGN_V1";
const MAX_WARMUP_ITERATIONS: u32 = 100_000;
const MAX_MEASURED_ITERATIONS: u32 = 1_000_000;
const MAX_SAMPLES: u32 = 10_000_000;
const MAX_CAMPAIGN_BYTES: usize = 256 * 1024 * 1024;
const SCORE_MILLION: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementStage {
    Compile,
    Parse,
    Extract,
    Validate,
    ContextCheck,
    CapsuleEncode,
    CapsuleCheck,
    Runtime,
    QuotientPad,
    AttackEvaluation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementMetric {
    WallClockTime,
    LogicalFuel,
    HostCallCount,
    MemoryAccessCount,
    ArtifactSize,
    PeakMemory,
    AttackScore,
}

impl MeasurementMetric {
    #[must_use]
    pub const fn expected_unit(self) -> MeasurementUnit {
        match self {
            Self::WallClockTime => MeasurementUnit::Nanoseconds,
            Self::LogicalFuel => MeasurementUnit::FuelUnits,
            Self::HostCallCount | Self::MemoryAccessCount => MeasurementUnit::Count,
            Self::ArtifactSize | Self::PeakMemory => MeasurementUnit::Bytes,
            Self::AttackScore => MeasurementUnit::ScoreMillionths,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementUnit {
    Nanoseconds,
    FuelUnits,
    Count,
    Bytes,
    ScoreMillionths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementProvenance {
    InjectedTestFixture,
    SoftwareFixture,
    OptInLocalWallClock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementFailureReason {
    ToolError,
    ParseError,
    ValidationError,
    CheckerRejected,
    RuntimeTrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementInconclusiveReason {
    Unsupported,
    ResourceBound,
    Timeout,
    MissingMetadata,
    CheckerDisagreement,
    WallClockNotOptedIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementOutcome {
    Success {
        value: u64,
    },
    Failure {
        reason: MeasurementFailureReason,
    },
    Inconclusive {
        reason: MeasurementInconclusiveReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub module_family_alias: u32,
    pub compiler_config_alias: u32,
    pub engine_alias: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkRunConfig {
    pub seed: u64,
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
    pub max_samples: u32,
    pub wall_clock_opt_in: bool,
    pub benchmark_plan_sha256: [u8; 32],
}

impl BenchmarkRunConfig {
    pub fn validate(self) -> Result<(), MeasurementContractError> {
        if self.warmup_iterations > MAX_WARMUP_ITERATIONS
            || self.measured_iterations == 0
            || self.measured_iterations > MAX_MEASURED_ITERATIONS
            || self.max_samples == 0
            || self.max_samples > MAX_SAMPLES
            || self.max_samples < self.measured_iterations
            || self.benchmark_plan_sha256 == [0; 32]
        {
            return Err(MeasurementContractError::InvalidRunConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OsFamily {
    Synthetic,
    Windows,
    Linux,
    Macos,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MachineArchitecture {
    Synthetic,
    X86_64,
    Aarch64,
    Wasm32,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CpuCountBucket {
    NotReported,
    One,
    Two,
    Four,
    Eight,
    Sixteen,
    ThirtyTwo,
    SixtyFourOrMore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryBucket {
    NotReported,
    UpToFourGib,
    UpToEightGib,
    UpToSixteenGib,
    UpToThirtyTwoGib,
    UpToSixtyFourGib,
    MoreThanSixtyFourGib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimerKind {
    LogicalCounter,
    MonotonicWallClock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedMachineMetadata {
    pub os_family: OsFamily,
    pub architecture: MachineArchitecture,
    pub logical_cpu_bucket: CpuCountBucket,
    pub memory_bucket: MemoryBucket,
    pub timer_kind: TimerKind,
    pub software_profile_sha256: [u8; 32],
}

impl SanitizedMachineMetadata {
    pub fn injected_fixture(
        software_profile_sha256: [u8; 32],
    ) -> Result<Self, MeasurementContractError> {
        let metadata = Self {
            os_family: OsFamily::Synthetic,
            architecture: MachineArchitecture::Synthetic,
            logical_cpu_bucket: CpuCountBucket::NotReported,
            memory_bucket: MemoryBucket::NotReported,
            timer_kind: TimerKind::LogicalCounter,
            software_profile_sha256,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn validate(self) -> Result<(), MeasurementContractError> {
        if self.software_profile_sha256 == [0; 32]
            || matches!(self.os_family, OsFamily::Synthetic)
                != matches!(self.architecture, MachineArchitecture::Synthetic)
            || (matches!(self.os_family, OsFamily::Synthetic)
                && self.timer_kind != TimerKind::LogicalCounter)
        {
            return Err(MeasurementContractError::InvalidMachineMetadata);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementEvidenceOrigin {
    InjectedTestFixture,
    SoftwareFixture,
    OptInLocalMeasurement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HardwareStatus {
    NotVerified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementSample {
    pub schema: String,
    pub stage: MeasurementStage,
    pub metric: MeasurementMetric,
    pub unit: MeasurementUnit,
    pub case: BenchmarkCase,
    pub iteration: u32,
    pub provenance: MeasurementProvenance,
    pub outcome: MeasurementOutcome,
    pub sample_sha256: [u8; 32],
}

impl MeasurementSample {
    pub fn build(
        stage: MeasurementStage,
        metric: MeasurementMetric,
        case: BenchmarkCase,
        iteration: u32,
        provenance: MeasurementProvenance,
        outcome: MeasurementOutcome,
    ) -> Result<Self, MeasurementContractError> {
        let unit = metric.expected_unit();
        validate_outcome(stage, metric, provenance, outcome)?;
        let mut sample = Self {
            schema: PERFORMANCE_SAMPLE_SCHEMA.to_owned(),
            stage,
            metric,
            unit,
            case,
            iteration,
            provenance,
            outcome,
            sample_sha256: [0; 32],
        };
        sample.sample_sha256 = sample.recomputed_sha256()?;
        Ok(sample)
    }

    pub fn validate(&self) -> Result<(), MeasurementContractError> {
        let expected = Self::build(
            self.stage,
            self.metric,
            self.case,
            self.iteration,
            self.provenance,
            self.outcome,
        )?;
        if self != &expected {
            return Err(MeasurementContractError::ArtifactMismatch);
        }
        Ok(())
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], MeasurementContractError> {
        let mut value = self.clone();
        value.sample_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| MeasurementContractError::Json)?;
        Ok(domain_hash(SAMPLE_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementCampaign {
    pub schema: String,
    pub config: BenchmarkRunConfig,
    pub machine: SanitizedMachineMetadata,
    pub samples: Vec<MeasurementSample>,
    pub evidence_origin: MeasurementEvidenceOrigin,
    pub hardware_status: HardwareStatus,
    pub artifact_sha256: [u8; 32],
}

impl MeasurementCampaign {
    pub fn build(
        config: BenchmarkRunConfig,
        machine: SanitizedMachineMetadata,
        mut samples: Vec<MeasurementSample>,
    ) -> Result<Self, MeasurementContractError> {
        config.validate()?;
        machine.validate()?;
        if samples.is_empty() || samples.len() > config.max_samples as usize {
            return Err(MeasurementContractError::SampleBound);
        }
        let mut keys = BTreeMap::new();
        let mut digests = BTreeMap::new();
        for sample in &samples {
            sample.validate()?;
            if sample.iteration >= config.measured_iterations {
                return Err(MeasurementContractError::IterationBound);
            }
            validate_wall_clock(config, machine, sample)?;
            let key = SampleKey::from(sample);
            if keys.insert(key, sample.sample_sha256).is_some() {
                return Err(MeasurementContractError::DuplicateSampleKey);
            }
            if let Some(existing) = digests.insert(sample.sample_sha256, key) {
                if existing != key {
                    return Err(MeasurementContractError::SampleCollision);
                }
            }
        }
        samples.sort_by_key(|sample| SampleKey::from(sample));
        let evidence_origin = derive_evidence_origin(&samples);
        let mut campaign = Self {
            schema: PERFORMANCE_CAMPAIGN_SCHEMA.to_owned(),
            config,
            machine,
            samples,
            evidence_origin,
            hardware_status: HardwareStatus::NotVerified,
            artifact_sha256: [0; 32],
        };
        campaign.artifact_sha256 = campaign.recomputed_sha256()?;
        Ok(campaign)
    }

    pub fn validate(&self) -> Result<(), MeasurementContractError> {
        let expected = Self::build(self.config, self.machine, self.samples.clone())?;
        if self != &expected {
            return Err(MeasurementContractError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, MeasurementContractError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| MeasurementContractError::Json)
    }

    pub fn decode_json(encoded: &[u8]) -> Result<Self, MeasurementContractError> {
        if encoded.is_empty() || encoded.len() > MAX_CAMPAIGN_BYTES {
            return Err(MeasurementContractError::Length);
        }
        let campaign: Self =
            serde_json::from_slice(encoded).map_err(|_| MeasurementContractError::Json)?;
        campaign.validate()?;
        if campaign.canonical_json()? != encoded {
            return Err(MeasurementContractError::NonCanonical);
        }
        Ok(campaign)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], MeasurementContractError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| MeasurementContractError::Json)?;
        Ok(domain_hash(CAMPAIGN_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MeasurementContractError {
    #[error("benchmark run configuration is invalid")]
    InvalidRunConfig,
    #[error("sanitized machine metadata is invalid")]
    InvalidMachineMetadata,
    #[error("measurement metric and unit are incompatible")]
    UnitMismatch,
    #[error("measurement outcome is invalid")]
    InvalidOutcome,
    #[error("wall-clock measurement was not explicitly enabled")]
    WallClockNotOptedIn,
    #[error("measurement sample exceeds its iteration bound")]
    IterationBound,
    #[error("measurement campaign exceeds its sample bound")]
    SampleBound,
    #[error("measurement sample key is duplicated")]
    DuplicateSampleKey,
    #[error("measurement sample digest collision")]
    SampleCollision,
    #[error("measurement artifact failed full recomputation")]
    ArtifactMismatch,
    #[error("measurement JSON is invalid")]
    Json,
    #[error("measurement JSON is not canonical")]
    NonCanonical,
    #[error("measurement artifact exceeds its byte bound")]
    Length,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SampleKey {
    stage: MeasurementStage,
    metric: MeasurementMetric,
    unit: MeasurementUnit,
    case: BenchmarkCase,
    iteration: u32,
    provenance: MeasurementProvenance,
}

impl From<&MeasurementSample> for SampleKey {
    fn from(sample: &MeasurementSample) -> Self {
        Self {
            stage: sample.stage,
            metric: sample.metric,
            unit: sample.unit,
            case: sample.case,
            iteration: sample.iteration,
            provenance: sample.provenance,
        }
    }
}

fn validate_outcome(
    stage: MeasurementStage,
    metric: MeasurementMetric,
    provenance: MeasurementProvenance,
    outcome: MeasurementOutcome,
) -> Result<(), MeasurementContractError> {
    if metric.expected_unit() == MeasurementUnit::ScoreMillionths
        && stage != MeasurementStage::AttackEvaluation
    {
        return Err(MeasurementContractError::UnitMismatch);
    }
    if metric == MeasurementMetric::WallClockTime
        && provenance != MeasurementProvenance::OptInLocalWallClock
    {
        return Err(MeasurementContractError::WallClockNotOptedIn);
    }
    if metric != MeasurementMetric::WallClockTime
        && provenance == MeasurementProvenance::OptInLocalWallClock
    {
        return Err(MeasurementContractError::UnitMismatch);
    }
    if let MeasurementOutcome::Success { value } = outcome {
        if metric == MeasurementMetric::WallClockTime && value == 0
            || metric == MeasurementMetric::AttackScore && value > SCORE_MILLION
        {
            return Err(MeasurementContractError::InvalidOutcome);
        }
    }
    Ok(())
}

fn validate_wall_clock(
    config: BenchmarkRunConfig,
    machine: SanitizedMachineMetadata,
    sample: &MeasurementSample,
) -> Result<(), MeasurementContractError> {
    if sample.metric == MeasurementMetric::WallClockTime
        && (!config.wall_clock_opt_in || machine.timer_kind != TimerKind::MonotonicWallClock)
    {
        return Err(MeasurementContractError::WallClockNotOptedIn);
    }
    Ok(())
}

fn derive_evidence_origin(samples: &[MeasurementSample]) -> MeasurementEvidenceOrigin {
    if samples
        .iter()
        .any(|sample| sample.provenance == MeasurementProvenance::OptInLocalWallClock)
    {
        MeasurementEvidenceOrigin::OptInLocalMeasurement
    } else if samples
        .iter()
        .any(|sample| sample.provenance == MeasurementProvenance::SoftwareFixture)
    {
        MeasurementEvidenceOrigin::SoftwareFixture
    } else {
        MeasurementEvidenceOrigin::InjectedTestFixture
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
