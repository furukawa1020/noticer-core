use crate::{
    BenchmarkCase, BenchmarkRunConfig, HardwareStatus, MeasurementCampaign,
    MeasurementContractError, MeasurementFailureReason, MeasurementMetric, MeasurementOutcome,
    MeasurementProvenance, MeasurementSample, MeasurementStage, SanitizedMachineMetadata,
    TimerKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use thiserror::Error;

pub const FIXTURE_PLAN_SCHEMA: &str = "quotient-seal.fixture-plan.v1";
pub const FIXTURE_RUN_SCHEMA: &str = "quotient-seal.fixture-run.v1";

const PLAN_DOMAIN: &[u8] = b"QUOTIENT_SEAL_FIXTURE_PLAN_V1";
const INVOCATION_DOMAIN: &[u8] = b"QUOTIENT_SEAL_FIXTURE_INVOCATION_V1";
const RANDOMNESS_DOMAIN: &[u8] = b"QUOTIENT_SEAL_FIXTURE_RANDOMNESS_V1";
const RUN_DOMAIN: &[u8] = b"QUOTIENT_SEAL_FIXTURE_RUN_V1";
const HARD_MAX_TASKS: u32 = 65_536;
const HARD_MAX_INVOCATIONS: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FixtureTask {
    pub stage: MeasurementStage,
    pub metric: MeasurementMetric,
    pub case: BenchmarkCase,
}

impl FixtureTask {
    pub fn validate(self) -> Result<(), FixtureRunnerError> {
        if self.metric == MeasurementMetric::WallClockTime
            || (self.metric == MeasurementMetric::AttackScore
                && self.stage != MeasurementStage::AttackEvaluation)
        {
            return Err(FixtureRunnerError::InvalidTask);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicFixturePlan {
    pub schema: String,
    pub tasks: Vec<FixtureTask>,
    pub artifact_sha256: [u8; 32],
}

impl DeterministicFixturePlan {
    pub fn build(mut tasks: Vec<FixtureTask>) -> Result<Self, FixtureRunnerError> {
        if tasks.is_empty() || tasks.len() > HARD_MAX_TASKS as usize {
            return Err(FixtureRunnerError::TaskBound);
        }
        for task in &tasks {
            task.validate()?;
        }
        tasks.sort_unstable();
        if tasks.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FixtureRunnerError::DuplicateTask);
        }
        let mut plan = Self {
            schema: FIXTURE_PLAN_SCHEMA.to_owned(),
            tasks,
            artifact_sha256: [0; 32],
        };
        plan.artifact_sha256 = plan.recomputed_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), FixtureRunnerError> {
        let expected = Self::build(self.tasks.clone())?;
        if self != &expected {
            return Err(FixtureRunnerError::ArtifactMismatch);
        }
        Ok(())
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], FixtureRunnerError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| FixtureRunnerError::Json)?;
        Ok(domain_hash(PLAN_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FixtureInvocationPhase {
    Warmup,
    Measured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureInvocation {
    pub seed: u64,
    pub task_index: u32,
    pub task: FixtureTask,
    pub phase: FixtureInvocationPhase,
    pub iteration: u32,
    pub public_randomness_word: u64,
}

pub trait SoftwareFixtureBenchmark {
    fn measure(&mut self, invocation: FixtureInvocation) -> MeasurementOutcome;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRunnerConfig {
    pub measurement: BenchmarkRunConfig,
    pub provenance: MeasurementProvenance,
    pub max_tasks: u32,
    pub max_invocations: u64,
}

impl FixtureRunnerConfig {
    pub fn validate(self) -> Result<(), FixtureRunnerError> {
        self.measurement
            .validate()
            .map_err(FixtureRunnerError::Contract)?;
        if self.measurement.wall_clock_opt_in
            || self.provenance == MeasurementProvenance::OptInLocalWallClock
            || self.max_tasks == 0
            || self.max_tasks > HARD_MAX_TASKS
            || self.max_invocations == 0
            || self.max_invocations > HARD_MAX_INVOCATIONS
        {
            return Err(FixtureRunnerError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureInvocationRecord {
    pub task_index: u32,
    pub phase: FixtureInvocationPhase,
    pub iteration: u32,
    pub public_randomness_word: u64,
    pub outcome: MeasurementOutcome,
    pub sample_sha256: Option<[u8; 32]>,
    pub record_sha256: [u8; 32],
}

impl FixtureInvocationRecord {
    fn build(
        task_index: u32,
        phase: FixtureInvocationPhase,
        iteration: u32,
        public_randomness_word: u64,
        outcome: MeasurementOutcome,
        sample_sha256: Option<[u8; 32]>,
    ) -> Result<Self, FixtureRunnerError> {
        if phase == FixtureInvocationPhase::Warmup && sample_sha256.is_some()
            || phase == FixtureInvocationPhase::Measured
                && sample_sha256.is_none_or(|digest| digest == [0; 32])
        {
            return Err(FixtureRunnerError::ArtifactMismatch);
        }
        let mut record = Self {
            task_index,
            phase,
            iteration,
            public_randomness_word,
            outcome,
            sample_sha256,
            record_sha256: [0; 32],
        };
        record.record_sha256 = record.recomputed_sha256()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), FixtureRunnerError> {
        let expected = Self::build(
            self.task_index,
            self.phase,
            self.iteration,
            self.public_randomness_word,
            self.outcome,
            self.sample_sha256,
        )?;
        if self != &expected {
            return Err(FixtureRunnerError::ArtifactMismatch);
        }
        Ok(())
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], FixtureRunnerError> {
        let mut value = self.clone();
        value.record_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| FixtureRunnerError::Json)?;
        Ok(domain_hash(INVOCATION_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRunSummary {
    pub warmup_success: u32,
    pub warmup_failure: u32,
    pub warmup_inconclusive: u32,
    pub measured_success: u32,
    pub measured_failure: u32,
    pub measured_inconclusive: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRunArtifact {
    pub schema: String,
    pub config: FixtureRunnerConfig,
    pub plan: DeterministicFixturePlan,
    pub campaign: MeasurementCampaign,
    pub invocations: Vec<FixtureInvocationRecord>,
    pub summary: FixtureRunSummary,
    pub evidence_origin: String,
    pub hardware_status: HardwareStatus,
    pub artifact_sha256: [u8; 32],
}

impl FixtureRunArtifact {
    pub fn validate(&self) -> Result<(), FixtureRunnerError> {
        self.config.validate()?;
        self.plan.validate()?;
        self.campaign
            .validate()
            .map_err(FixtureRunnerError::Contract)?;
        validate_run_links(
            self.config,
            &self.plan,
            &self.campaign,
            &self.invocations,
            self.summary,
        )?;
        if self.schema != FIXTURE_RUN_SCHEMA
            || self.evidence_origin != provenance_label(self.config.provenance)
            || self.hardware_status != HardwareStatus::NotVerified
            || self.artifact_sha256 != self.recomputed_sha256()?
        {
            return Err(FixtureRunnerError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, FixtureRunnerError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| FixtureRunnerError::Json)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], FixtureRunnerError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| FixtureRunnerError::Json)?;
        Ok(domain_hash(RUN_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FixtureRunnerError {
    #[error("software fixture task is invalid")]
    InvalidTask,
    #[error("software fixture plan contains a duplicate task")]
    DuplicateTask,
    #[error("software fixture task bound was reached")]
    TaskBound,
    #[error("software fixture runner configuration is invalid")]
    InvalidConfig,
    #[error("software fixture invocation bound was reached")]
    InvocationBound,
    #[error("software fixture benchmark plan digest mismatch")]
    PlanMismatch,
    #[error("software fixture artifact failed full recomputation")]
    ArtifactMismatch,
    #[error("software fixture JSON serialization failed")]
    Json,
    #[error("measurement contract rejected the fixture artifact: {0}")]
    Contract(MeasurementContractError),
}

pub fn run_software_fixture<F: SoftwareFixtureBenchmark>(
    config: FixtureRunnerConfig,
    plan: DeterministicFixturePlan,
    machine: SanitizedMachineMetadata,
    fixture: &mut F,
) -> Result<FixtureRunArtifact, FixtureRunnerError> {
    config.validate()?;
    plan.validate()?;
    machine.validate().map_err(FixtureRunnerError::Contract)?;
    if machine.timer_kind != TimerKind::LogicalCounter {
        return Err(FixtureRunnerError::InvalidConfig);
    }
    if plan.tasks.len() > config.max_tasks as usize
        || config.measurement.benchmark_plan_sha256 != plan.artifact_sha256
    {
        return Err(FixtureRunnerError::PlanMismatch);
    }
    let per_task = u64::from(config.measurement.warmup_iterations)
        .checked_add(u64::from(config.measurement.measured_iterations))
        .ok_or(FixtureRunnerError::InvocationBound)?;
    let expected_invocations = (plan.tasks.len() as u64)
        .checked_mul(per_task)
        .ok_or(FixtureRunnerError::InvocationBound)?;
    let expected_samples = (plan.tasks.len() as u64)
        .checked_mul(u64::from(config.measurement.measured_iterations))
        .ok_or(FixtureRunnerError::InvocationBound)?;
    if expected_invocations > config.max_invocations
        || expected_samples > u64::from(config.measurement.max_samples)
    {
        return Err(FixtureRunnerError::InvocationBound);
    }

    let mut invocations = Vec::with_capacity(expected_invocations as usize);
    let mut samples = Vec::with_capacity(expected_samples as usize);
    for (task_index, task) in plan.tasks.iter().copied().enumerate() {
        for iteration in 0..config.measurement.warmup_iterations {
            let word = randomness_word(
                config.measurement.seed,
                plan.artifact_sha256,
                task_index as u32,
                FixtureInvocationPhase::Warmup,
                iteration,
            );
            let outcome = execute_fixture(
                fixture,
                FixtureInvocation {
                    seed: config.measurement.seed,
                    task_index: task_index as u32,
                    task,
                    phase: FixtureInvocationPhase::Warmup,
                    iteration,
                    public_randomness_word: word,
                },
            );
            invocations.push(FixtureInvocationRecord::build(
                task_index as u32,
                FixtureInvocationPhase::Warmup,
                iteration,
                word,
                outcome,
                None,
            )?);
        }
        for iteration in 0..config.measurement.measured_iterations {
            let word = randomness_word(
                config.measurement.seed,
                plan.artifact_sha256,
                task_index as u32,
                FixtureInvocationPhase::Measured,
                iteration,
            );
            let outcome = execute_fixture(
                fixture,
                FixtureInvocation {
                    seed: config.measurement.seed,
                    task_index: task_index as u32,
                    task,
                    phase: FixtureInvocationPhase::Measured,
                    iteration,
                    public_randomness_word: word,
                },
            );
            let sample = MeasurementSample::build(
                task.stage,
                task.metric,
                task.case,
                iteration,
                config.provenance,
                outcome,
            )
            .map_err(FixtureRunnerError::Contract)?;
            invocations.push(FixtureInvocationRecord::build(
                task_index as u32,
                FixtureInvocationPhase::Measured,
                iteration,
                word,
                outcome,
                Some(sample.sample_sha256),
            )?);
            samples.push(sample);
        }
    }
    let campaign = MeasurementCampaign::build(config.measurement, machine, samples)
        .map_err(FixtureRunnerError::Contract)?;
    let summary = summarize(&invocations);
    validate_run_links(config, &plan, &campaign, &invocations, summary)?;
    let mut artifact = FixtureRunArtifact {
        schema: FIXTURE_RUN_SCHEMA.to_owned(),
        config,
        plan,
        campaign,
        invocations,
        summary,
        evidence_origin: provenance_label(config.provenance).to_owned(),
        hardware_status: HardwareStatus::NotVerified,
        artifact_sha256: [0; 32],
    };
    artifact.artifact_sha256 = artifact.recomputed_sha256()?;
    Ok(artifact)
}

fn execute_fixture<F: SoftwareFixtureBenchmark>(
    fixture: &mut F,
    invocation: FixtureInvocation,
) -> MeasurementOutcome {
    catch_unwind(AssertUnwindSafe(|| fixture.measure(invocation))).unwrap_or(
        MeasurementOutcome::Failure {
            reason: MeasurementFailureReason::ToolError,
        },
    )
}

fn validate_run_links(
    config: FixtureRunnerConfig,
    plan: &DeterministicFixturePlan,
    campaign: &MeasurementCampaign,
    invocations: &[FixtureInvocationRecord],
    summary: FixtureRunSummary,
) -> Result<(), FixtureRunnerError> {
    if campaign.config != config.measurement
        || campaign.machine.timer_kind != TimerKind::LogicalCounter
        || campaign.hardware_status != HardwareStatus::NotVerified
        || config.measurement.benchmark_plan_sha256 != plan.artifact_sha256
        || plan.tasks.len() > config.max_tasks as usize
    {
        return Err(FixtureRunnerError::ArtifactMismatch);
    }
    let expected_invocations = plan.tasks.len()
        * (config.measurement.warmup_iterations + config.measurement.measured_iterations) as usize;
    if invocations.len() != expected_invocations
        || invocations.len() > config.max_invocations as usize
    {
        return Err(FixtureRunnerError::InvocationBound);
    }
    let mut measured_samples = BTreeMap::new();
    for sample in &campaign.samples {
        let key = (sample.stage, sample.metric, sample.case, sample.iteration);
        if measured_samples.insert(key, sample).is_some() {
            return Err(FixtureRunnerError::ArtifactMismatch);
        }
    }
    let mut cursor = 0;
    let mut seen_records = BTreeSet::new();
    for (task_index, task) in plan.tasks.iter().copied().enumerate() {
        for (phase, count) in [
            (
                FixtureInvocationPhase::Warmup,
                config.measurement.warmup_iterations,
            ),
            (
                FixtureInvocationPhase::Measured,
                config.measurement.measured_iterations,
            ),
        ] {
            for iteration in 0..count {
                let record = invocations
                    .get(cursor)
                    .ok_or(FixtureRunnerError::ArtifactMismatch)?;
                record.validate()?;
                let word = randomness_word(
                    config.measurement.seed,
                    plan.artifact_sha256,
                    task_index as u32,
                    phase,
                    iteration,
                );
                if record.task_index != task_index as u32
                    || record.phase != phase
                    || record.iteration != iteration
                    || record.public_randomness_word != word
                    || !seen_records.insert(record.record_sha256)
                {
                    return Err(FixtureRunnerError::ArtifactMismatch);
                }
                match phase {
                    FixtureInvocationPhase::Warmup if record.sample_sha256.is_none() => {}
                    FixtureInvocationPhase::Measured => {
                        let sample = measured_samples
                            .get(&(task.stage, task.metric, task.case, iteration))
                            .ok_or(FixtureRunnerError::ArtifactMismatch)?;
                        if record.sample_sha256 != Some(sample.sample_sha256)
                            || record.outcome != sample.outcome
                            || sample.provenance != config.provenance
                        {
                            return Err(FixtureRunnerError::ArtifactMismatch);
                        }
                    }
                    _ => return Err(FixtureRunnerError::ArtifactMismatch),
                }
                cursor += 1;
            }
        }
    }
    if summary != summarize(invocations) {
        return Err(FixtureRunnerError::ArtifactMismatch);
    }
    Ok(())
}

fn summarize(invocations: &[FixtureInvocationRecord]) -> FixtureRunSummary {
    let mut summary = FixtureRunSummary {
        warmup_success: 0,
        warmup_failure: 0,
        warmup_inconclusive: 0,
        measured_success: 0,
        measured_failure: 0,
        measured_inconclusive: 0,
    };
    for record in invocations {
        match (record.phase, record.outcome) {
            (FixtureInvocationPhase::Warmup, MeasurementOutcome::Success { .. }) => {
                summary.warmup_success += 1;
            }
            (FixtureInvocationPhase::Warmup, MeasurementOutcome::Failure { .. }) => {
                summary.warmup_failure += 1;
            }
            (FixtureInvocationPhase::Warmup, MeasurementOutcome::Inconclusive { .. }) => {
                summary.warmup_inconclusive += 1;
            }
            (FixtureInvocationPhase::Measured, MeasurementOutcome::Success { .. }) => {
                summary.measured_success += 1;
            }
            (FixtureInvocationPhase::Measured, MeasurementOutcome::Failure { .. }) => {
                summary.measured_failure += 1;
            }
            (FixtureInvocationPhase::Measured, MeasurementOutcome::Inconclusive { .. }) => {
                summary.measured_inconclusive += 1;
            }
        }
    }
    summary
}

fn randomness_word(
    seed: u64,
    plan_sha256: [u8; 32],
    task_index: u32,
    phase: FixtureInvocationPhase,
    iteration: u32,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(RANDOMNESS_DOMAIN);
    hasher.update(seed.to_be_bytes());
    hasher.update(plan_sha256);
    hasher.update(task_index.to_be_bytes());
    hasher.update([match phase {
        FixtureInvocationPhase::Warmup => 0,
        FixtureInvocationPhase::Measured => 1,
    }]);
    hasher.update(iteration.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    )
}

const fn provenance_label(provenance: MeasurementProvenance) -> &'static str {
    match provenance {
        MeasurementProvenance::InjectedTestFixture => "INJECTED_TEST_FIXTURE",
        MeasurementProvenance::SoftwareFixture => "SOFTWARE_FIXTURE",
        MeasurementProvenance::OptInLocalWallClock => "OPT_IN_LOCAL_WALL_CLOCK",
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
