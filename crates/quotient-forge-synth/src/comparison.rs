//! Reproducible three-strategy CEGIS comparison artifacts.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::session::SessionArtifact;

pub const CEGIS_COMPARISON_SCHEMA_V1: &str = "noticer.quotient_forge.cegis_comparison.v1";
pub const CEGIS_BACKEND_RUN_SCHEMA_V1: &str = "noticer.quotient_forge.cegis_backend_run.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonMethod {
    OneShot,
    NonIncrementalCegis,
    IncrementalCegis,
}

impl ComparisonMethod {
    pub const ALL: [Self; 3] = [
        Self::OneShot,
        Self::NonIncrementalCegis,
        Self::IncrementalCegis,
    ];

    pub const fn directory_name(self) -> &'static str {
        match self {
            Self::OneShot => "one_shot",
            Self::NonIncrementalCegis => "non_incremental_cegis",
            Self::IncrementalCegis => "incremental_cegis",
        }
    }

    fn relative_result_path(self) -> String {
        format!("backends/{}/result.json", self.directory_name())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FrozenComparisonBounds {
    pub machine_states: u32,
    pub trace_horizon: u32,
    pub candidate_limit: u64,
    pub wall_time_limit_ms: u64,
    pub memory_limit_bytes: u64,
}

impl FrozenComparisonBounds {
    fn validate(&self) -> Result<(), ComparisonError> {
        if self.machine_states == 0
            || self.trace_horizon == 0
            || self.candidate_limit == 0
            || self.wall_time_limit_ms == 0
            || self.memory_limit_bytes == 0
        {
            return Err(ComparisonError::InvalidBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FrozenComparisonCase {
    pub case_id: String,
    pub problem_sha256: String,
    pub seed: u64,
    pub bounds: FrozenComparisonBounds,
    pub checker_contract_sha256: String,
}

impl FrozenComparisonCase {
    pub fn validate(&self) -> Result<(), ComparisonError> {
        if self.case_id.is_empty()
            || self.case_id.len() > 128
            || !self
                .case_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ComparisonError::InvalidCaseId);
        }
        require_sha256("problem_sha256", &self.problem_sha256)?;
        require_sha256("checker_contract_sha256", &self.checker_contract_sha256)?;
        self.bounds.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    NotVerified,
    SolverUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendInconclusiveReason {
    Timeout,
    ResourceExhausted,
    SolverUnavailable,
    NotVerified,
    ProcessFailure,
    CheckerInconclusive,
    CandidateLimit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ComparisonOutcome {
    Sat,
    BoundedUnsat,
    Inconclusive { reason: BackendInconclusiveReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConclusiveDecision {
    Sat,
    BoundedUnsat,
}

impl ComparisonOutcome {
    fn conclusive(&self) -> Option<ConclusiveDecision> {
        match self {
            Self::Sat => Some(ConclusiveDecision::Sat),
            Self::BoundedUnsat => Some(ConclusiveDecision::BoundedUnsat),
            Self::Inconclusive { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComparisonMetrics {
    pub solver_calls: u64,
    pub checker_calls: u64,
    pub candidates: u64,
    pub blockers: u64,
    pub restarts: u64,
    pub core_rechecks: u64,
}

impl From<&SessionArtifact> for ComparisonMetrics {
    fn from(session: &SessionArtifact) -> Self {
        Self {
            solver_calls: session.metrics.solver_calls,
            checker_calls: session.metrics.checker_calls,
            candidates: session.metrics.candidates,
            blockers: session.metrics.accepted_blockers,
            restarts: session.metrics.restarts,
            core_rechecks: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Observed,
    NotVerified,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceMeasurement {
    pub status: ObservationStatus,
    pub value: Option<u64>,
}

impl ResourceMeasurement {
    pub const fn observed(value: u64) -> Self {
        Self {
            status: ObservationStatus::Observed,
            value: Some(value),
        }
    }

    pub const fn not_verified() -> Self {
        Self {
            status: ObservationStatus::NotVerified,
            value: None,
        }
    }

    pub const fn unsupported() -> Self {
        Self {
            status: ObservationStatus::Unsupported,
            value: None,
        }
    }

    fn validate(&self) -> Result<(), ComparisonError> {
        if (self.status == ObservationStatus::Observed) != self.value.is_some() {
            return Err(ComparisonError::InvalidResourceObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceObservations {
    pub wall_time_ms: ResourceMeasurement,
    pub peak_memory_bytes: ResourceMeasurement,
}

impl ResourceObservations {
    fn validate(&self) -> Result<(), ComparisonError> {
        self.wall_time_ms.validate()?;
        self.peak_memory_bytes.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreObservationStatus {
    NotRequested,
    Unsupported,
    Missing,
    Rejected,
    Validated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoreObservation {
    pub status: CoreObservationStatus,
    pub named_assertions: u64,
    pub core_size: Option<u64>,
    pub audit_artifact_sha256: Option<String>,
}

impl CoreObservation {
    pub const fn not_requested() -> Self {
        Self {
            status: CoreObservationStatus::NotRequested,
            named_assertions: 0,
            core_size: None,
            audit_artifact_sha256: None,
        }
    }

    fn validate(&self) -> Result<(), ComparisonError> {
        if let Some(digest) = &self.audit_artifact_sha256 {
            require_sha256("audit_artifact_sha256", digest)?;
        }
        match self.status {
            CoreObservationStatus::Validated => {
                if self.core_size == Some(0)
                    || self.core_size.is_none()
                    || self.audit_artifact_sha256.is_none()
                {
                    return Err(ComparisonError::InvalidCoreObservation);
                }
            }
            CoreObservationStatus::NotRequested
            | CoreObservationStatus::Unsupported
            | CoreObservationStatus::Missing => {
                if self.core_size.is_some() || self.audit_artifact_sha256.is_some() {
                    return Err(ComparisonError::InvalidCoreObservation);
                }
            }
            CoreObservationStatus::Rejected => {}
        }
        Ok(())
    }
}

pub struct BackendRunInput {
    pub method: ComparisonMethod,
    pub verification_status: VerificationStatus,
    pub outcome: ComparisonOutcome,
    pub checked_candidate_sha256: Option<String>,
    pub candidate_independently_checked: bool,
    pub checker_artifact_sha256: Option<String>,
    pub backend_artifact_sha256: Option<String>,
    pub session_artifact_sha256: Option<String>,
    pub metrics: ComparisonMetrics,
    pub resources: ResourceObservations,
    pub core: CoreObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendRunArtifact {
    pub schema_version: String,
    pub method: ComparisonMethod,
    pub case_id: String,
    pub problem_sha256: String,
    pub seed: u64,
    pub bounds: FrozenComparisonBounds,
    pub checker_contract_sha256: String,
    pub verification_status: VerificationStatus,
    pub outcome: ComparisonOutcome,
    pub checked_candidate_sha256: Option<String>,
    pub candidate_independently_checked: bool,
    pub checker_artifact_sha256: Option<String>,
    pub backend_artifact_sha256: Option<String>,
    pub session_artifact_sha256: Option<String>,
    pub metrics: ComparisonMetrics,
    pub resources: ResourceObservations,
    pub core: CoreObservation,
    pub artifact_sha256: String,
}

impl BackendRunArtifact {
    pub fn new(
        case: &FrozenComparisonCase,
        input: BackendRunInput,
    ) -> Result<Self, ComparisonError> {
        case.validate()?;
        let mut artifact = Self {
            schema_version: CEGIS_BACKEND_RUN_SCHEMA_V1.to_owned(),
            method: input.method,
            case_id: case.case_id.clone(),
            problem_sha256: case.problem_sha256.clone(),
            seed: case.seed,
            bounds: case.bounds.clone(),
            checker_contract_sha256: case.checker_contract_sha256.clone(),
            verification_status: input.verification_status,
            outcome: input.outcome,
            checked_candidate_sha256: input.checked_candidate_sha256,
            candidate_independently_checked: input.candidate_independently_checked,
            checker_artifact_sha256: input.checker_artifact_sha256,
            backend_artifact_sha256: input.backend_artifact_sha256,
            session_artifact_sha256: input.session_artifact_sha256,
            metrics: input.metrics,
            resources: input.resources,
            core: input.core,
            artifact_sha256: String::new(),
        };
        artifact.validate_payload(case)?;
        artifact.artifact_sha256 = artifact.digest()?;
        artifact.validate(case)?;
        Ok(artifact)
    }

    pub fn validate(&self, case: &FrozenComparisonCase) -> Result<(), ComparisonError> {
        self.validate_payload(case)?;
        require_sha256("artifact_sha256", &self.artifact_sha256)?;
        if self.digest()? != self.artifact_sha256 {
            return Err(ComparisonError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }

    fn validate_payload(&self, case: &FrozenComparisonCase) -> Result<(), ComparisonError> {
        if self.schema_version != CEGIS_BACKEND_RUN_SCHEMA_V1 {
            return Err(ComparisonError::SchemaVersion);
        }
        if self.case_id != case.case_id
            || self.problem_sha256 != case.problem_sha256
            || self.seed != case.seed
            || self.bounds != case.bounds
            || self.checker_contract_sha256 != case.checker_contract_sha256
        {
            return Err(ComparisonError::CaseMismatch);
        }
        require_sha256("problem_sha256", &self.problem_sha256)?;
        require_sha256("checker_contract_sha256", &self.checker_contract_sha256)?;
        for (field, digest) in [
            ("checked_candidate_sha256", &self.checked_candidate_sha256),
            ("checker_artifact_sha256", &self.checker_artifact_sha256),
            ("backend_artifact_sha256", &self.backend_artifact_sha256),
            ("session_artifact_sha256", &self.session_artifact_sha256),
        ] {
            if let Some(digest) = digest {
                require_sha256(field, digest)?;
            }
        }
        self.resources.validate()?;
        self.core.validate()?;
        if self.metrics.checker_calls > self.metrics.candidates {
            return Err(ComparisonError::InvalidMetrics);
        }
        match &self.outcome {
            ComparisonOutcome::Sat => {
                if self.verification_status != VerificationStatus::Verified
                    || self.checked_candidate_sha256.is_none()
                    || !self.candidate_independently_checked
                    || self.checker_artifact_sha256.is_none()
                    || self.backend_artifact_sha256.is_none()
                    || self.metrics.checker_calls == 0
                {
                    return Err(ComparisonError::UncheckedCandidate);
                }
            }
            ComparisonOutcome::BoundedUnsat => {
                if self.verification_status != VerificationStatus::Verified
                    || self.checked_candidate_sha256.is_some()
                    || self.candidate_independently_checked
                {
                    return Err(ComparisonError::InvalidOutcomeBoundary);
                }
            }
            ComparisonOutcome::Inconclusive { reason } => {
                if self.checked_candidate_sha256.is_some()
                    || self.candidate_independently_checked
                    || !matches!(
                        (self.verification_status, reason),
                        (
                            VerificationStatus::NotVerified,
                            BackendInconclusiveReason::NotVerified
                        ) | (
                            VerificationStatus::SolverUnavailable,
                            BackendInconclusiveReason::SolverUnavailable
                        )
                    ) && self.verification_status != VerificationStatus::Verified
                    || self.verification_status == VerificationStatus::Verified
                        && matches!(
                            reason,
                            BackendInconclusiveReason::NotVerified
                                | BackendInconclusiveReason::SolverUnavailable
                        )
                {
                    return Err(ComparisonError::InvalidOutcomeBoundary);
                }
            }
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, ComparisonError> {
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        canonical_json_sha256(&payload)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionConsistency {
    AllConclusiveAgree,
    ConclusiveDisagreement,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateHashRelation {
    AllEqual,
    DifferentCheckedCandidates,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendFileEntry {
    pub method: ComparisonMethod,
    pub relative_path: String,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CegisComparisonArtifact {
    pub schema_version: String,
    pub frozen_case: FrozenComparisonCase,
    pub backend_runs: Vec<BackendRunArtifact>,
    pub backend_files: Vec<BackendFileEntry>,
    pub decision_consistency: DecisionConsistency,
    pub candidate_hash_relation: CandidateHashRelation,
    pub comparison_accepted: bool,
    pub performance_claimed: bool,
    pub artifact_sha256: String,
}

impl CegisComparisonArtifact {
    pub fn build(
        frozen_case: FrozenComparisonCase,
        mut backend_runs: Vec<BackendRunArtifact>,
    ) -> Result<Self, ComparisonError> {
        frozen_case.validate()?;
        backend_runs.sort_by_key(|run| run.method);
        validate_methods(&backend_runs)?;
        for run in &backend_runs {
            run.validate(&frozen_case)?;
        }
        let decision_consistency = derive_decision_consistency(&backend_runs);
        let candidate_hash_relation = derive_candidate_relation(&backend_runs);
        let backend_files = backend_runs
            .iter()
            .map(|run| BackendFileEntry {
                method: run.method,
                relative_path: run.method.relative_result_path(),
                artifact_sha256: run.artifact_sha256.clone(),
            })
            .collect();
        let mut artifact = Self {
            schema_version: CEGIS_COMPARISON_SCHEMA_V1.to_owned(),
            frozen_case,
            backend_runs,
            backend_files,
            decision_consistency,
            candidate_hash_relation,
            comparison_accepted: decision_consistency == DecisionConsistency::AllConclusiveAgree,
            performance_claimed: false,
            artifact_sha256: String::new(),
        };
        artifact.artifact_sha256 = artifact.digest()?;
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), ComparisonError> {
        if self.schema_version != CEGIS_COMPARISON_SCHEMA_V1 {
            return Err(ComparisonError::SchemaVersion);
        }
        self.frozen_case.validate()?;
        validate_methods(&self.backend_runs)?;
        for run in &self.backend_runs {
            run.validate(&self.frozen_case)?;
        }
        let expected_files = self
            .backend_runs
            .iter()
            .map(|run| BackendFileEntry {
                method: run.method,
                relative_path: run.method.relative_result_path(),
                artifact_sha256: run.artifact_sha256.clone(),
            })
            .collect::<Vec<_>>();
        let expected_consistency = derive_decision_consistency(&self.backend_runs);
        if self.backend_files != expected_files
            || self.decision_consistency != expected_consistency
            || self.candidate_hash_relation != derive_candidate_relation(&self.backend_runs)
            || self.comparison_accepted
                != (expected_consistency == DecisionConsistency::AllConclusiveAgree)
            || self.performance_claimed
        {
            return Err(ComparisonError::InconsistentManifest);
        }
        require_sha256("artifact_sha256", &self.artifact_sha256)?;
        if self.digest()? != self.artifact_sha256 {
            return Err(ComparisonError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, ComparisonError> {
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        canonical_json_sha256(&payload)
    }
}

#[derive(Debug)]
pub struct ComparisonWriteReceipt {
    pub manifest_path: PathBuf,
    pub backend_result_paths: Vec<PathBuf>,
}

pub fn write_comparison_artifact(
    root: impl AsRef<Path>,
    artifact: &CegisComparisonArtifact,
) -> Result<ComparisonWriteReceipt, ComparisonError> {
    artifact.validate()?;
    let root = root.as_ref();
    fs::create_dir_all(root)?;
    let mut backend_result_paths = Vec::new();
    for run in &artifact.backend_runs {
        let directory = root.join("backends").join(run.method.directory_name());
        fs::create_dir_all(&directory)?;
        let path = directory.join("result.json");
        write_json(&path, run)?;
        backend_result_paths.push(path);
    }
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, artifact)?;
    Ok(ComparisonWriteReceipt {
        manifest_path,
        backend_result_paths,
    })
}

#[derive(Debug, Error)]
pub enum ComparisonError {
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("case id must be a portable identifier")]
    InvalidCaseId,
    #[error("all frozen bounds must be greater than zero")]
    InvalidBounds,
    #[error("backend run does not match the frozen case")]
    CaseMismatch,
    #[error("comparison requires exactly one run for each method")]
    InvalidMethodSet,
    #[error("resource observation status and value disagree")]
    InvalidResourceObservation,
    #[error("core observation fields disagree")]
    InvalidCoreObservation,
    #[error("backend metrics are inconsistent")]
    InvalidMetrics,
    #[error("SAT candidate was not independently checked")]
    UncheckedCandidate,
    #[error("verification status and outcome disagree")]
    InvalidOutcomeBoundary,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("comparison manifest fields are inconsistent")]
    InconsistentManifest,
    #[error("{0} does not match its canonical payload")]
    DigestMismatch(&'static str),
    #[error("artifact serialization failed")]
    Serialization,
    #[error("artifact write failed: {0}")]
    Io(#[from] std::io::Error),
}

fn validate_methods(runs: &[BackendRunArtifact]) -> Result<(), ComparisonError> {
    if runs.len() != ComparisonMethod::ALL.len()
        || runs
            .iter()
            .zip(ComparisonMethod::ALL)
            .any(|(run, expected)| run.method != expected)
    {
        return Err(ComparisonError::InvalidMethodSet);
    }
    Ok(())
}

fn derive_decision_consistency(runs: &[BackendRunArtifact]) -> DecisionConsistency {
    let decisions = runs
        .iter()
        .filter_map(|run| run.outcome.conclusive())
        .collect::<Vec<_>>();
    if decisions.len() != ComparisonMethod::ALL.len() {
        DecisionConsistency::Incomplete
    } else if decisions.windows(2).all(|pair| pair[0] == pair[1]) {
        DecisionConsistency::AllConclusiveAgree
    } else {
        DecisionConsistency::ConclusiveDisagreement
    }
}

fn derive_candidate_relation(runs: &[BackendRunArtifact]) -> CandidateHashRelation {
    if !runs.iter().all(|run| run.outcome == ComparisonOutcome::Sat) {
        return CandidateHashRelation::NotApplicable;
    }
    let candidates = runs
        .iter()
        .filter_map(|run| run.checked_candidate_sha256.as_deref())
        .collect::<Vec<_>>();
    if candidates.len() == ComparisonMethod::ALL.len()
        && candidates.windows(2).all(|pair| pair[0] == pair[1])
    {
        CandidateHashRelation::AllEqual
    } else {
        CandidateHashRelation::DifferentCheckedCandidates
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ComparisonError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| ComparisonError::Serialization)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), ComparisonError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ComparisonError::InvalidSha256(field))
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, ComparisonError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ComparisonError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
