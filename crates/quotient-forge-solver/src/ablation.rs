//! Real-backend ablation for validated quotient reduction.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use quotient_forge_synth::{
    find_feasible, synthesis_problem_sha256, InconclusiveReason, ReleaseMachine, SearchStats,
    SynthesisOutcome, SynthesisProblem,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::{
    solve, BackendConfig, BackendStatus, SolverKind, SolverRuntime, SolverSelection,
};
use crate::comparison::{run_qbf, BackendComparisonConfig, BackendObservation, ComparisonStatus};
use crate::qbf_solver::QbfSolverAdapter;

pub const REDUCTION_ABLATION_SCHEMA_V1: &str = "noticer.quotient_forge.reduction_ablation.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AblationBackend {
    Cegis,
    Smt,
    Qbf,
}

impl AblationBackend {
    pub const ALL: [Self; 3] = [Self::Cegis, Self::Smt, Self::Qbf];

    const fn directory(self) -> &'static str {
        match self {
            Self::Cegis => "cegis",
            Self::Smt => "smt",
            Self::Qbf => "qbf",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReductionMode {
    Disabled,
    Enabled,
}

impl ReductionMode {
    const fn filename(self) -> &'static str {
        match self {
            Self::Disabled => "disabled.json",
            Self::Enabled => "enabled.json",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AblationRunStatus {
    CandidateVerified,
    UnrealizableWithinBounds,
    Timeout,
    ResourceExhausted,
    SolverUnavailable,
    SolverUnknown,
    MalformedOutput,
    NotRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementStatus {
    Observed,
    NotVerified,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Measurement {
    pub status: MeasurementStatus,
    pub value: Option<u64>,
}

impl Measurement {
    pub const fn observed(value: u64) -> Self {
        Self {
            status: MeasurementStatus::Observed,
            value: Some(value),
        }
    }

    pub const fn not_verified() -> Self {
        Self {
            status: MeasurementStatus::NotVerified,
            value: None,
        }
    }

    pub const fn unsupported() -> Self {
        Self {
            status: MeasurementStatus::Unsupported,
            value: None,
        }
    }

    fn validate(&self) -> bool {
        (self.status == MeasurementStatus::Observed) == self.value.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AblationRunMetrics {
    pub solver_calls: Measurement,
    pub checker_calls: Measurement,
    pub candidates: Measurement,
    pub blockers: Measurement,
    pub variables: Measurement,
    pub clauses: Measurement,
    pub wall_time_ms: Measurement,
    pub peak_memory_bytes: Measurement,
    pub peak_memory_scope: String,
}

impl AblationRunMetrics {
    fn validate(&self) -> bool {
        [
            &self.solver_calls,
            &self.checker_calls,
            &self.candidates,
            &self.blockers,
            &self.variables,
            &self.clauses,
            &self.wall_time_ms,
            &self.peak_memory_bytes,
        ]
        .into_iter()
        .all(Measurement::validate)
            && !self.peak_memory_scope.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AblationRun {
    pub backend: AblationBackend,
    pub reduction: ReductionMode,
    pub engine: String,
    pub status: AblationRunStatus,
    pub candidate_sha256: Option<String>,
    pub candidate_independently_checked: bool,
    pub metrics: AblationRunMetrics,
    pub diagnostic: Option<String>,
}

impl AblationRun {
    fn validate(&self) -> bool {
        if self.engine.is_empty()
            || !self.metrics.validate()
            || self
                .candidate_sha256
                .as_ref()
                .is_some_and(|value| !is_sha256(value))
        {
            return false;
        }
        if self.status == AblationRunStatus::CandidateVerified {
            self.candidate_independently_checked && self.candidate_sha256.is_some()
        } else {
            !self.candidate_independently_checked
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AblationMetricDirection {
    Decreased,
    Equal,
    Increased,
    NotVerified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetricChange {
    pub before: Measurement,
    pub after: Measurement,
    pub direction: AblationMetricDirection,
    pub after_over_before_ppm: Option<u64>,
}

impl MetricChange {
    fn new(before: Measurement, after: Measurement) -> Self {
        let (direction, after_over_before_ppm) = match (before.value, after.value) {
            (Some(before_value), Some(after_value)) => {
                let direction = match after_value.cmp(&before_value) {
                    std::cmp::Ordering::Less => AblationMetricDirection::Decreased,
                    std::cmp::Ordering::Equal => AblationMetricDirection::Equal,
                    std::cmp::Ordering::Greater => AblationMetricDirection::Increased,
                };
                let ratio = (before_value > 0).then(|| {
                    after_value
                        .saturating_mul(1_000_000)
                        .checked_div(before_value)
                        .unwrap_or(u64::MAX)
                });
                (direction, ratio)
            }
            _ => (AblationMetricDirection::NotVerified, None),
        };
        Self {
            before,
            after,
            direction,
            after_over_before_ppm,
        }
    }

    fn validate(&self) -> bool {
        self.before.validate()
            && self.after.validate()
            && *self == Self::new(self.before.clone(), self.after.clone())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionConsistency {
    Agree,
    Disagree,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AblationPair {
    pub backend: AblationBackend,
    pub disabled: AblationRun,
    pub enabled: AblationRun,
    pub decision_consistency: DecisionConsistency,
    pub candidate_hash_equal: Option<bool>,
    pub candidate_checker_gate_passed: bool,
    pub solver_call_change: MetricChange,
    pub checker_call_change: MetricChange,
    pub candidate_change: MetricChange,
    pub blocker_change: MetricChange,
    pub wall_time_change: MetricChange,
    pub peak_memory_change: MetricChange,
}

impl AblationPair {
    fn build(backend: AblationBackend, disabled: AblationRun, enabled: AblationRun) -> Self {
        let decision_consistency = match (
            conclusive_decision(disabled.status),
            conclusive_decision(enabled.status),
        ) {
            (Some(left), Some(right)) if left == right => DecisionConsistency::Agree,
            (Some(_), Some(_)) => DecisionConsistency::Disagree,
            _ => DecisionConsistency::Incomplete,
        };
        let candidate_hash_equal = disabled
            .candidate_sha256
            .as_ref()
            .zip(enabled.candidate_sha256.as_ref())
            .map(|(left, right)| left == right);
        let candidate_checker_gate_passed = [&disabled, &enabled].into_iter().all(|run| {
            run.status != AblationRunStatus::CandidateVerified
                || (run.candidate_independently_checked && run.candidate_sha256.is_some())
        });
        Self {
            backend,
            solver_call_change: MetricChange::new(
                disabled.metrics.solver_calls.clone(),
                enabled.metrics.solver_calls.clone(),
            ),
            checker_call_change: MetricChange::new(
                disabled.metrics.checker_calls.clone(),
                enabled.metrics.checker_calls.clone(),
            ),
            candidate_change: MetricChange::new(
                disabled.metrics.candidates.clone(),
                enabled.metrics.candidates.clone(),
            ),
            blocker_change: MetricChange::new(
                disabled.metrics.blockers.clone(),
                enabled.metrics.blockers.clone(),
            ),
            wall_time_change: MetricChange::new(
                disabled.metrics.wall_time_ms.clone(),
                enabled.metrics.wall_time_ms.clone(),
            ),
            peak_memory_change: MetricChange::new(
                disabled.metrics.peak_memory_bytes.clone(),
                enabled.metrics.peak_memory_bytes.clone(),
            ),
            disabled,
            enabled,
            decision_consistency,
            candidate_hash_equal,
            candidate_checker_gate_passed,
        }
    }

    fn validate(&self) -> bool {
        if self.disabled.backend != self.backend
            || self.enabled.backend != self.backend
            || self.disabled.reduction != ReductionMode::Disabled
            || self.enabled.reduction != ReductionMode::Enabled
            || !self.disabled.validate()
            || !self.enabled.validate()
            || !self.solver_call_change.validate()
            || !self.checker_call_change.validate()
            || !self.candidate_change.validate()
            || !self.blocker_change.validate()
            || !self.wall_time_change.validate()
            || !self.peak_memory_change.validate()
        {
            return false;
        }
        let rebuilt = Self::build(self.backend, self.disabled.clone(), self.enabled.clone());
        rebuilt.decision_consistency == self.decision_consistency
            && rebuilt.candidate_hash_equal == self.candidate_hash_equal
            && rebuilt.candidate_checker_gate_passed == self.candidate_checker_gate_passed
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StructuralReduction {
    pub source_state_to_class: MetricChange,
    pub machine_symbol: MetricChange,
    pub machine_state_bound: MetricChange,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticGate {
    Pass,
    Disable,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceSignal {
    Improved,
    Regressed,
    MixedOrEqual,
    NotVerified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReductionEvidenceBinding {
    pub quotient_artifact_sha256: String,
    pub preservation_artifact_sha256: String,
    pub lift_artifact_sha256: String,
    pub solution_set_artifact_sha256: String,
}

impl ReductionEvidenceBinding {
    pub fn new(
        quotient_artifact_sha256: impl Into<String>,
        preservation_artifact_sha256: impl Into<String>,
        lift_artifact_sha256: impl Into<String>,
        solution_set_artifact_sha256: impl Into<String>,
    ) -> Result<Self, AblationError> {
        let binding = Self {
            quotient_artifact_sha256: quotient_artifact_sha256.into(),
            preservation_artifact_sha256: preservation_artifact_sha256.into(),
            lift_artifact_sha256: lift_artifact_sha256.into(),
            solution_set_artifact_sha256: solution_set_artifact_sha256.into(),
        };
        if !binding.validate() {
            return Err(AblationError::InvalidEvidenceBinding);
        }
        Ok(binding)
    }

    fn validate(&self) -> bool {
        [
            &self.quotient_artifact_sha256,
            &self.preservation_artifact_sha256,
            &self.lift_artifact_sha256,
            &self.solution_set_artifact_sha256,
        ]
        .into_iter()
        .all(|value| is_sha256(value))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReductionAblationArtifact {
    pub schema_version: String,
    pub case_id: String,
    pub seed: u64,
    pub state_bound: u32,
    pub unreduced_problem_sha256: String,
    pub reduced_problem_sha256: String,
    pub evidence: ReductionEvidenceBinding,
    pub structural_reduction: StructuralReduction,
    pub backends: Vec<AblationPair>,
    pub semantic_gate: SemanticGate,
    pub reduction_enabled: bool,
    pub performance_signal: PerformanceSignal,
    pub performance_claimed: bool,
    pub artifact_sha256: String,
}

impl ReductionAblationArtifact {
    pub fn backend(&self, backend: AblationBackend) -> Option<&AblationPair> {
        self.backends.iter().find(|pair| pair.backend == backend)
    }

    pub fn validate(&self) -> Result<(), AblationError> {
        if self.schema_version != REDUCTION_ABLATION_SCHEMA_V1 {
            return Err(AblationError::SchemaVersion);
        }
        if self.case_id.is_empty()
            || self.state_bound == 0
            || !is_sha256(&self.unreduced_problem_sha256)
            || !is_sha256(&self.reduced_problem_sha256)
            || !is_sha256(&self.artifact_sha256)
            || !self.evidence.validate()
            || self.backends.len() != AblationBackend::ALL.len()
            || self
                .backends
                .iter()
                .zip(AblationBackend::ALL)
                .any(|(pair, expected)| pair.backend != expected || !pair.validate())
            || !self.structural_reduction.source_state_to_class.validate()
            || !self.structural_reduction.machine_symbol.validate()
            || !self.structural_reduction.machine_state_bound.validate()
            || self.performance_claimed
        {
            return Err(AblationError::InvalidArtifact);
        }
        let gate = semantic_gate(&self.backends);
        if self.semantic_gate != gate
            || self.reduction_enabled != (gate == SemanticGate::Pass)
            || self.performance_signal != performance_signal(&self.backends)
        {
            return Err(AblationError::InvalidArtifact);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(AblationError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AblationManifestReceipt {
    pub manifest_path: PathBuf,
    pub backend_paths: Vec<PathBuf>,
}

#[derive(Debug, Error)]
pub enum AblationError {
    #[error("case identifier must be non-empty")]
    EmptyCaseId,
    #[error("reduction evidence binding is invalid")]
    InvalidEvidenceBinding,
    #[error("ablation configuration is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("unreduced and reduced inputs do not share one frozen semantic frame")]
    CaseMismatch,
    #[error("problem is invalid: {0}")]
    Problem(String),
    #[error("backend execution failed: {0}")]
    Execution(String),
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("reduction ablation artifact is inconsistent")]
    InvalidArtifact,
    #[error("artifact digest does not match its canonical payload")]
    DigestMismatch,
    #[error("artifact serialization failed")]
    Serialization,
    #[error("manifest I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[allow(clippy::too_many_arguments)]
pub fn run_reduction_ablation(
    case_id: impl Into<String>,
    unreduced: &SynthesisProblem,
    reduced: &SynthesisProblem,
    quotient_class_count: u32,
    evidence: ReductionEvidenceBinding,
    config: &BackendComparisonConfig,
    smt_runtime: Option<&dyn SolverRuntime>,
    qbf_adapter: Option<&QbfSolverAdapter>,
) -> Result<ReductionAblationArtifact, AblationError> {
    let case_id = case_id.into();
    if case_id.is_empty() {
        return Err(AblationError::EmptyCaseId);
    }
    validate_config(config)?;
    validate_same_case(unreduced, reduced, quotient_class_count)?;
    if !evidence.validate() {
        return Err(AblationError::InvalidEvidenceBinding);
    }
    let unreduced_problem_sha256 = synthesis_problem_sha256(unreduced)
        .map_err(|error| AblationError::Problem(error.to_string()))?;
    let reduced_problem_sha256 = synthesis_problem_sha256(reduced)
        .map_err(|error| AblationError::Problem(error.to_string()))?;

    let cegis_disabled = run_cegis(unreduced, config, ReductionMode::Disabled)?;
    let cegis_enabled = run_cegis(reduced, config, ReductionMode::Enabled)?;
    let smt_disabled = run_smt(unreduced, config, smt_runtime, ReductionMode::Disabled);
    let smt_enabled = run_smt(reduced, config, smt_runtime, ReductionMode::Enabled);
    let qbf_disabled = run_qbf_backend(unreduced, config, qbf_adapter, ReductionMode::Disabled);
    let qbf_enabled = run_qbf_backend(reduced, config, qbf_adapter, ReductionMode::Enabled);
    let backends = vec![
        AblationPair::build(AblationBackend::Cegis, cegis_disabled, cegis_enabled),
        AblationPair::build(AblationBackend::Smt, smt_disabled, smt_enabled),
        AblationPair::build(AblationBackend::Qbf, qbf_disabled, qbf_enabled),
    ];
    let source_state_count = u64::try_from(unreduced.plant_states.len()).unwrap_or(u64::MAX);
    let structural_reduction = StructuralReduction {
        source_state_to_class: MetricChange::new(
            Measurement::observed(source_state_count),
            Measurement::observed(u64::from(quotient_class_count)),
        ),
        machine_symbol: MetricChange::new(
            Measurement::observed(u64::from(unreduced.machine_symbol_count)),
            Measurement::observed(u64::from(reduced.machine_symbol_count)),
        ),
        machine_state_bound: MetricChange::new(
            Measurement::observed(u64::from(config.state_bound)),
            Measurement::observed(u64::from(config.state_bound)),
        ),
    };
    let gate = semantic_gate(&backends);
    let mut artifact = ReductionAblationArtifact {
        schema_version: REDUCTION_ABLATION_SCHEMA_V1.to_owned(),
        case_id,
        seed: config.seed,
        state_bound: config.state_bound,
        unreduced_problem_sha256,
        reduced_problem_sha256,
        evidence,
        structural_reduction,
        semantic_gate: gate,
        reduction_enabled: gate == SemanticGate::Pass,
        performance_signal: performance_signal(&backends),
        performance_claimed: false,
        backends,
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate()?;
    Ok(artifact)
}

pub fn write_reduction_ablation(
    root: &Path,
    artifact: &ReductionAblationArtifact,
) -> Result<AblationManifestReceipt, AblationError> {
    artifact.validate()?;
    fs::create_dir_all(root)?;
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, artifact)?;
    let mut backend_paths = Vec::new();
    for pair in &artifact.backends {
        let directory = root.join("backends").join(pair.backend.directory());
        fs::create_dir_all(&directory)?;
        for run in [&pair.disabled, &pair.enabled] {
            let path = directory.join(run.reduction.filename());
            write_json(&path, run)?;
            backend_paths.push(path);
        }
    }
    Ok(AblationManifestReceipt {
        manifest_path,
        backend_paths,
    })
}

fn validate_config(config: &BackendComparisonConfig) -> Result<(), AblationError> {
    if config.state_bound == 0
        || config.solver_timeout.is_zero()
        || config.qbf_truth_variable_limit == 0
    {
        return Err(AblationError::InvalidConfig("zero bound or limit"));
    }
    if config.run_smt && config.smt_selection == SolverSelection::Explicit(SolverKind::Exhaustive) {
        return Err(AblationError::InvalidConfig(
            "SMT ablation cannot select exhaustive",
        ));
    }
    Ok(())
}

fn validate_same_case(
    unreduced: &SynthesisProblem,
    reduced: &SynthesisProblem,
    quotient_class_count: u32,
) -> Result<(), AblationError> {
    let same_transition_frame = unreduced.plant_transitions.len()
        == reduced.plant_transitions.len()
        && unreduced
            .plant_transitions
            .iter()
            .zip(&reduced.plant_transitions)
            .all(|(left, right)| {
                (left.from, left.input, left.to) == (right.from, right.input, right.to)
            });
    let same_frame = unreduced.horizon == reduced.horizon
        && unreduced.plant_states == reduced.plant_states
        && same_transition_frame
        && unreduced.inputs == reduced.inputs
        && unreduced.semantics == reduced.semantics
        && unreduced.faults == reduced.faults
        && unreduced.observers == reduced.observers
        && unreduced.initial_pairs == reduced.initial_pairs
        && unreduced.outputs == reduced.outputs;
    if !same_frame
        || quotient_class_count == 0
        || quotient_class_count as usize > unreduced.plant_states.len()
        || reduced.machine_symbol_count > unreduced.machine_symbol_count
    {
        return Err(AblationError::CaseMismatch);
    }
    Ok(())
}

fn run_cegis(
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
    reduction: ReductionMode,
) -> Result<AblationRun, AblationError> {
    let started = Instant::now();
    let mut limits = config.exhaustive_limits;
    limits.max_states = config.state_bound;
    limits.seed = config.seed;
    let outcome = find_feasible(problem, limits)
        .map_err(|error| AblationError::Execution(error.to_string()))?;
    let elapsed = elapsed_ms(started);
    let (status, candidate, stats, diagnostic) = match outcome {
        SynthesisOutcome::Realizable(report) => (
            AblationRunStatus::CandidateVerified,
            Some(report.machine),
            report.stats,
            None,
        ),
        SynthesisOutcome::Unrealizable(report) => (
            AblationRunStatus::UnrealizableWithinBounds,
            None,
            report.stats,
            Some(format!(
                "bounded negative through {} states",
                report.searched_through_states
            )),
        ),
        SynthesisOutcome::Inconclusive { reason, stats } => {
            let status = match reason {
                InconclusiveReason::TimeLimit { .. } => AblationRunStatus::Timeout,
                InconclusiveReason::CandidateLimit { .. }
                | InconclusiveReason::CheckerResource
                | InconclusiveReason::EnumerationDomain { .. } => {
                    AblationRunStatus::ResourceExhausted
                }
            };
            (status, None, stats, Some(format!("{reason:?}")))
        }
    };
    Ok(AblationRun {
        backend: AblationBackend::Cegis,
        reduction,
        engine: "in-process-cegis-enumerator".to_owned(),
        candidate_sha256: candidate.as_ref().map(machine_sha256),
        candidate_independently_checked: candidate.is_some(),
        status,
        metrics: search_metrics(&stats, elapsed),
        diagnostic,
    })
}

fn run_smt(
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
    runtime: Option<&dyn SolverRuntime>,
    reduction: ReductionMode,
) -> AblationRun {
    if !config.run_smt {
        return empty_run(
            AblationBackend::Smt,
            reduction,
            "not-requested",
            AblationRunStatus::NotRun,
            "SMT backend was disabled",
        );
    }
    let Some(runtime) = runtime else {
        return empty_run(
            AblationBackend::Smt,
            reduction,
            "external-smt",
            AblationRunStatus::SolverUnavailable,
            "SMT runtime was not configured",
        );
    };
    let started = Instant::now();
    let mut exhaustive_limits = config.exhaustive_limits;
    exhaustive_limits.max_states = config.state_bound;
    exhaustive_limits.seed = config.seed;
    let backend_config = BackendConfig {
        selection: config.smt_selection,
        state_bound: config.state_bound,
        solver_timeout: config.solver_timeout,
        max_cegis_rounds: config.max_cegis_rounds,
        exhaustive_fallback_max_cells: 0,
        exhaustive_limits,
        ..BackendConfig::default()
    };
    let result = solve(problem, &backend_config, runtime);
    let elapsed = elapsed_ms(started);
    let Ok(result) = result else {
        return empty_observed_run(
            AblationBackend::Smt,
            reduction,
            "external-smt",
            AblationRunStatus::MalformedOutput,
            elapsed,
            "SMT encoding failed",
        );
    };
    let engine = result
        .artifact
        .selected
        .map(solver_name)
        .unwrap_or("external-smt")
        .to_owned();
    let status = match result.status {
        BackendStatus::Sat if result.machine.is_some() => AblationRunStatus::CandidateVerified,
        BackendStatus::Sat | BackendStatus::MalformedOutput => AblationRunStatus::MalformedOutput,
        BackendStatus::Unsat => AblationRunStatus::UnrealizableWithinBounds,
        BackendStatus::Timeout => AblationRunStatus::Timeout,
        BackendStatus::NotInstalled => AblationRunStatus::SolverUnavailable,
        BackendStatus::ResourceExhausted | BackendStatus::OutputLimitExceeded => {
            AblationRunStatus::ResourceExhausted
        }
    };
    let solver_calls = u64::try_from(result.artifact.phases.len()).unwrap_or(u64::MAX);
    let blockers = u64::try_from(result.artifact.hard_blockers).unwrap_or(u64::MAX);
    let candidate_count = match status {
        AblationRunStatus::CandidateVerified => Measurement::observed(blockers.saturating_add(1)),
        AblationRunStatus::UnrealizableWithinBounds
        | AblationRunStatus::Timeout
        | AblationRunStatus::SolverUnavailable => Measurement::observed(blockers),
        _ => Measurement::not_verified(),
    };
    let peak = process_peak_memory_bytes();
    AblationRun {
        backend: AblationBackend::Smt,
        reduction,
        engine,
        status,
        candidate_sha256: result.machine.as_ref().map(machine_sha256),
        candidate_independently_checked: result.machine.is_some(),
        metrics: AblationRunMetrics {
            solver_calls: Measurement::observed(solver_calls),
            checker_calls: candidate_count.clone(),
            candidates: candidate_count,
            blockers: Measurement::observed(blockers),
            variables: Measurement::not_verified(),
            clauses: Measurement::not_verified(),
            wall_time_ms: Measurement::observed(elapsed),
            peak_memory_bytes: peak.map_or_else(Measurement::not_verified, Measurement::observed),
            peak_memory_scope: peak_scope(),
        },
        diagnostic: result.detail,
    }
}

fn run_qbf_backend(
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
    adapter: Option<&QbfSolverAdapter>,
    reduction: ReductionMode,
) -> AblationRun {
    let (observation, qdimacs_sha256) = run_qbf(problem, config, adapter);
    qbf_run(observation, qdimacs_sha256.is_some(), reduction)
}

fn qbf_run(
    observation: BackendObservation,
    solver_called: bool,
    reduction: ReductionMode,
) -> AblationRun {
    let status = map_comparison_status(observation.status);
    let peak_memory_bytes = observation.resources.peak_memory_bytes.map_or_else(
        || {
            if observation.resources.peak_memory_scope == "NOT_VERIFIED" {
                Measurement::not_verified()
            } else {
                Measurement::unsupported()
            }
        },
        Measurement::observed,
    );
    let candidate_count = u64::from(observation.candidate_decision.is_some());
    AblationRun {
        backend: AblationBackend::Qbf,
        reduction,
        engine: observation.engine,
        status,
        candidate_sha256: observation.candidate_sha256,
        candidate_independently_checked: observation.independently_checked,
        metrics: AblationRunMetrics {
            solver_calls: Measurement::observed(u64::from(solver_called)),
            checker_calls: Measurement::observed(candidate_count),
            candidates: Measurement::observed(candidate_count),
            blockers: Measurement::unsupported(),
            variables: observation
                .resources
                .variables
                .map_or_else(Measurement::not_verified, |value| {
                    Measurement::observed(u64::from(value))
                }),
            clauses: observation
                .resources
                .clauses
                .map_or_else(Measurement::not_verified, |value| {
                    Measurement::observed(u64::from(value))
                }),
            wall_time_ms: Measurement::observed(observation.resources.wall_time_ms),
            peak_memory_bytes,
            peak_memory_scope: observation.resources.peak_memory_scope,
        },
        diagnostic: observation.diagnostic,
    }
}

fn search_metrics(stats: &SearchStats, elapsed: u64) -> AblationRunMetrics {
    let peak = process_peak_memory_bytes();
    AblationRunMetrics {
        solver_calls: Measurement::observed(0),
        checker_calls: Measurement::observed(stats.checker_calls),
        candidates: Measurement::observed(stats.generated_candidates),
        blockers: Measurement::observed(stats.counterexamples),
        variables: Measurement::unsupported(),
        clauses: Measurement::unsupported(),
        wall_time_ms: Measurement::observed(elapsed),
        peak_memory_bytes: peak.map_or_else(Measurement::not_verified, Measurement::observed),
        peak_memory_scope: peak_scope(),
    }
}

fn empty_run(
    backend: AblationBackend,
    reduction: ReductionMode,
    engine: &str,
    status: AblationRunStatus,
    diagnostic: &str,
) -> AblationRun {
    AblationRun {
        backend,
        reduction,
        engine: engine.to_owned(),
        status,
        candidate_sha256: None,
        candidate_independently_checked: false,
        metrics: AblationRunMetrics {
            solver_calls: Measurement::not_verified(),
            checker_calls: Measurement::not_verified(),
            candidates: Measurement::not_verified(),
            blockers: Measurement::not_verified(),
            variables: Measurement::not_verified(),
            clauses: Measurement::not_verified(),
            wall_time_ms: Measurement::not_verified(),
            peak_memory_bytes: Measurement::not_verified(),
            peak_memory_scope: "NOT_VERIFIED".to_owned(),
        },
        diagnostic: Some(diagnostic.to_owned()),
    }
}

fn empty_observed_run(
    backend: AblationBackend,
    reduction: ReductionMode,
    engine: &str,
    status: AblationRunStatus,
    elapsed: u64,
    diagnostic: &str,
) -> AblationRun {
    let mut run = empty_run(backend, reduction, engine, status, diagnostic);
    run.metrics.solver_calls = Measurement::observed(0);
    run.metrics.wall_time_ms = Measurement::observed(elapsed);
    run
}

fn semantic_gate(backends: &[AblationPair]) -> SemanticGate {
    if backends.iter().any(|pair| {
        pair.decision_consistency == DecisionConsistency::Disagree
            || !pair.candidate_checker_gate_passed
    }) {
        SemanticGate::Disable
    } else if backends
        .iter()
        .any(|pair| pair.decision_consistency == DecisionConsistency::Incomplete)
    {
        SemanticGate::Inconclusive
    } else {
        SemanticGate::Pass
    }
}

fn performance_signal(backends: &[AblationPair]) -> PerformanceSignal {
    let directions = backends
        .iter()
        .map(|pair| pair.wall_time_change.direction)
        .collect::<Vec<_>>();
    if directions.contains(&AblationMetricDirection::NotVerified) {
        PerformanceSignal::NotVerified
    } else if directions.contains(&AblationMetricDirection::Increased) {
        PerformanceSignal::Regressed
    } else if directions
        .iter()
        .all(|direction| *direction == AblationMetricDirection::Decreased)
    {
        PerformanceSignal::Improved
    } else {
        PerformanceSignal::MixedOrEqual
    }
}

fn conclusive_decision(status: AblationRunStatus) -> Option<bool> {
    match status {
        AblationRunStatus::CandidateVerified => Some(true),
        AblationRunStatus::UnrealizableWithinBounds => Some(false),
        _ => None,
    }
}

fn map_comparison_status(status: ComparisonStatus) -> AblationRunStatus {
    match status {
        ComparisonStatus::CandidateVerified => AblationRunStatus::CandidateVerified,
        ComparisonStatus::UnrealizableWithinBounds => AblationRunStatus::UnrealizableWithinBounds,
        ComparisonStatus::Timeout => AblationRunStatus::Timeout,
        ComparisonStatus::ResourceExhausted => AblationRunStatus::ResourceExhausted,
        ComparisonStatus::SolverUnavailable => AblationRunStatus::SolverUnavailable,
        ComparisonStatus::SolverUnknown => AblationRunStatus::SolverUnknown,
        ComparisonStatus::MalformedOutput => AblationRunStatus::MalformedOutput,
        ComparisonStatus::NotRun => AblationRunStatus::NotRun,
    }
}

fn solver_name(kind: SolverKind) -> &'static str {
    match kind {
        SolverKind::Cvc5 => "cvc5",
        SolverKind::Z3 => "z3",
        SolverKind::Exhaustive => "exhaustive",
    }
}

fn machine_sha256(machine: &ReleaseMachine) -> String {
    format!("{:x}", Sha256::digest(machine.canonical_bytes()))
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(target_os = "linux")]
fn process_peak_memory_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let kilobytes = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kilobytes.checked_mul(1024)
}

#[cfg(not(target_os = "linux"))]
const fn process_peak_memory_bytes() -> Option<u64> {
    None
}

fn peak_scope() -> String {
    if cfg!(target_os = "linux") {
        "HARNESS_PROCESS_VM_HWM".to_owned()
    } else {
        "NOT_VERIFIED".to_owned()
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), AblationError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| AblationError::Serialization)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, AblationError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AblationError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
