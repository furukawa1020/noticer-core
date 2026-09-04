use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use quotient_forge_check::CheckLimits;
use quotient_forge_synth::{
    find_feasible, InconclusiveReason, ReleaseMachine, SearchStats, SynthesisError,
    SynthesisLimits, SynthesisOutcome, SynthesisProblem,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::{
    solve, BackendConfig, BackendStatus, SolverKind, SolverRuntime, SolverSelection,
};
use crate::qbf::{
    compile_bounded_safety_game, evaluate_qbf_reference_model, QbfCompilation, QbfCompileError,
    QbfCompileLimits,
};
use crate::qbf_model::{check_qbf_candidate, QbfCandidateDecisionArtifact};
use crate::qbf_solver::{
    QbfCandidateStatus, QbfSolverAdapter, QbfSolverMetadata, QbfSolverResultArtifact, QbfSolverRun,
    QbfSolverStatus, QBF_SOLVER_RESULT_SCHEMA_V1,
};

pub const BACKEND_COMPARISON_SCHEMA_V1: &str = "noticer.quotient_forge.backend_comparison.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComparisonStatus {
    CandidateVerified,
    UnrealizableWithinBounds,
    Timeout,
    ResourceExhausted,
    SolverUnavailable,
    SolverUnknown,
    MalformedOutput,
    NotRun,
}

#[derive(Clone, Debug)]
pub struct BackendComparisonConfig {
    pub seed: u64,
    pub state_bound: u32,
    pub symmetry_breaking: bool,
    pub run_smt: bool,
    pub smt_selection: SolverSelection,
    pub solver_timeout: Duration,
    pub max_cegis_rounds: u32,
    pub qbf_truth_variable_limit: usize,
    pub exhaustive_limits: SynthesisLimits,
    pub checker_limits: CheckLimits,
}

impl Default for BackendComparisonConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            state_bound: 1,
            symmetry_breaking: true,
            run_smt: false,
            smt_selection: SolverSelection::Auto,
            solver_timeout: Duration::from_secs(30),
            max_cegis_rounds: 10_000,
            qbf_truth_variable_limit: 24,
            exhaustive_limits: SynthesisLimits::default(),
            checker_limits: CheckLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceObservation {
    pub wall_time_ms: u64,
    pub peak_memory_bytes: Option<u64>,
    pub peak_memory_scope: String,
    pub variables: Option<u32>,
    pub clauses: Option<u32>,
    pub rounds: Option<u32>,
    pub generated_candidates: Option<u64>,
    pub checker_calls: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendObservation {
    pub backend: String,
    pub engine: String,
    pub status: ComparisonStatus,
    pub bounded_only: bool,
    pub independently_checked: bool,
    pub candidate_sha256: Option<String>,
    pub resources: ResourceObservation,
    pub solver_result: Option<QbfSolverResultArtifact>,
    pub candidate_decision: Option<QbfCandidateDecisionArtifact>,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonAgreements {
    pub exhaustive_qbf_decision: Option<bool>,
    pub smt_qbf_decision: Option<bool>,
    pub exhaustive_qbf_candidate_sha256: Option<bool>,
    pub smt_qbf_candidate_sha256: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendComparisonArtifact {
    pub schema_version: String,
    pub seed: u64,
    pub state_bound: u32,
    pub symmetry_breaking_requested: bool,
    pub symmetry_breaking_effective: String,
    pub qdimacs_sha256: Option<String>,
    pub exhaustive: BackendObservation,
    pub smt: BackendObservation,
    pub qbf: BackendObservation,
    pub agreements: ComparisonAgreements,
}

#[derive(Debug, Error)]
pub enum BackendComparisonError {
    #[error("invalid backend comparison configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("exhaustive synthesis failed: {0}")]
    Synthesis(#[from] SynthesisError),
    #[error("backend comparison JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("backend comparison I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl BackendComparisonArtifact {
    pub fn json_bytes(&self) -> Result<Vec<u8>, BackendComparisonError> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn write_to_directory(&self, directory: &Path) -> Result<(), BackendComparisonError> {
        fs::create_dir_all(directory)?;
        fs::create_dir_all(directory.join("backends/exhaustive"))?;
        fs::create_dir_all(directory.join("backends/smt"))?;
        fs::create_dir_all(directory.join("backends/qbf"))?;
        fs::write(directory.join("comparison.json"), self.json_bytes()?)?;
        write_json(
            &directory.join("backends/exhaustive/result.json"),
            &self.exhaustive,
        )?;
        write_json(&directory.join("backends/smt/result.json"), &self.smt)?;
        write_json(&directory.join("backends/qbf/result.json"), &self.qbf)?;
        Ok(())
    }
}

pub fn compare_bounded_backends(
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
    smt_runtime: Option<&dyn SolverRuntime>,
    qbf_adapter: Option<&QbfSolverAdapter>,
) -> Result<BackendComparisonArtifact, BackendComparisonError> {
    validate_config(config)?;
    let exhaustive = run_exhaustive(problem, config)?;
    let smt = run_smt(problem, config, smt_runtime);
    let (qbf, qdimacs_sha256) = run_qbf(problem, config, qbf_adapter);
    let agreements = ComparisonAgreements {
        exhaustive_qbf_decision: decision_agreement(&exhaustive, &qbf),
        smt_qbf_decision: decision_agreement(&smt, &qbf),
        exhaustive_qbf_candidate_sha256: candidate_agreement(&exhaustive, &qbf),
        smt_qbf_candidate_sha256: candidate_agreement(&smt, &qbf),
    };

    Ok(BackendComparisonArtifact {
        schema_version: BACKEND_COMPARISON_SCHEMA_V1.to_owned(),
        seed: config.seed,
        state_bound: config.state_bound,
        symmetry_breaking_requested: config.symmetry_breaking,
        symmetry_breaking_effective: "CANONICAL_RELEASE_MACHINE_V1_ALWAYS_ON".to_owned(),
        qdimacs_sha256,
        exhaustive,
        smt,
        qbf,
        agreements,
    })
}

fn validate_config(config: &BackendComparisonConfig) -> Result<(), BackendComparisonError> {
    if config.state_bound == 0 {
        return Err(BackendComparisonError::InvalidConfig(
            "state_bound must be positive",
        ));
    }
    if config.solver_timeout.is_zero() {
        return Err(BackendComparisonError::InvalidConfig(
            "solver_timeout must be positive",
        ));
    }
    if config.qbf_truth_variable_limit == 0 {
        return Err(BackendComparisonError::InvalidConfig(
            "qbf_truth_variable_limit must be positive",
        ));
    }
    if config.run_smt && config.smt_selection == SolverSelection::Explicit(SolverKind::Exhaustive) {
        return Err(BackendComparisonError::InvalidConfig(
            "SMT comparison cannot select exhaustive",
        ));
    }
    Ok(())
}

fn run_exhaustive(
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
) -> Result<BackendObservation, BackendComparisonError> {
    let started = Instant::now();
    let mut limits = config.exhaustive_limits;
    limits.max_states = config.state_bound;
    limits.seed = config.seed;
    let outcome = find_feasible(problem, limits)?;
    let elapsed = elapsed_ms(started);
    let (status, machine, stats, diagnostic) = match outcome {
        SynthesisOutcome::Realizable(report) => (
            ComparisonStatus::CandidateVerified,
            Some(report.machine),
            report.stats,
            None,
        ),
        SynthesisOutcome::Unrealizable(report) => (
            ComparisonStatus::UnrealizableWithinBounds,
            None,
            report.stats,
            Some(format!(
                "bounded negative through {} machine states",
                report.searched_through_states
            )),
        ),
        SynthesisOutcome::Inconclusive { reason, stats } => {
            let status = match reason {
                InconclusiveReason::TimeLimit { .. } => ComparisonStatus::Timeout,
                InconclusiveReason::CandidateLimit { .. }
                | InconclusiveReason::CheckerResource
                | InconclusiveReason::EnumerationDomain { .. } => {
                    ComparisonStatus::ResourceExhausted
                }
            };
            (status, None, stats, Some(format!("{reason:?}")))
        }
    };
    let candidate_sha256 = machine.as_ref().map(machine_sha256);
    Ok(BackendObservation {
        backend: "exhaustive".to_owned(),
        engine: "in-process-enumerator".to_owned(),
        status,
        bounded_only: true,
        independently_checked: machine.is_some(),
        candidate_sha256,
        resources: resources(elapsed, None, None, None, Some(&stats)),
        solver_result: None,
        candidate_decision: None,
        diagnostic,
    })
}

fn run_smt(
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
    runtime: Option<&dyn SolverRuntime>,
) -> BackendObservation {
    if !config.run_smt {
        return empty_observation(
            "smt",
            "not-requested",
            ComparisonStatus::NotRun,
            "SMT backend was disabled",
        );
    }
    let Some(runtime) = runtime else {
        return empty_observation(
            "smt",
            "external-smt",
            ComparisonStatus::SolverUnavailable,
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
    match result {
        Err(error) => BackendObservation {
            backend: "smt".to_owned(),
            engine: "external-smt".to_owned(),
            status: ComparisonStatus::MalformedOutput,
            bounded_only: true,
            independently_checked: false,
            candidate_sha256: None,
            resources: resources(elapsed, None, None, None, None),
            solver_result: None,
            candidate_decision: None,
            diagnostic: Some(error.to_string()),
        },
        Ok(result) => {
            let selected = result.artifact.selected.map(solver_label);
            let engine = selected.unwrap_or_else(|| "external-smt".to_owned());
            let candidate_sha256 = result.machine.as_ref().map(machine_sha256);
            let independently_checked = result.machine.is_some();
            let status = match result.status {
                BackendStatus::Sat if independently_checked => ComparisonStatus::CandidateVerified,
                BackendStatus::Sat => ComparisonStatus::MalformedOutput,
                BackendStatus::Unsat => ComparisonStatus::UnrealizableWithinBounds,
                BackendStatus::Timeout => ComparisonStatus::Timeout,
                BackendStatus::NotInstalled => ComparisonStatus::SolverUnavailable,
                BackendStatus::ResourceExhausted | BackendStatus::OutputLimitExceeded => {
                    ComparisonStatus::ResourceExhausted
                }
                BackendStatus::MalformedOutput => ComparisonStatus::MalformedOutput,
            };
            BackendObservation {
                backend: "smt".to_owned(),
                engine,
                status,
                bounded_only: true,
                independently_checked,
                candidate_sha256,
                resources: resources(
                    elapsed,
                    None,
                    None,
                    Some(result.artifact.cegis_rounds),
                    None,
                ),
                solver_result: None,
                candidate_decision: None,
                diagnostic: result.detail,
            }
        }
    }
}

fn run_qbf(
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
    adapter: Option<&QbfSolverAdapter>,
) -> (BackendObservation, Option<String>) {
    let started = Instant::now();
    let compile_limits = QbfCompileLimits {
        max_machine_states: config.state_bound,
        seed: config.seed,
        ..QbfCompileLimits::default()
    };
    let compilation = match compile_bounded_safety_game(problem, compile_limits) {
        Ok(compilation) => compilation,
        Err(error) => {
            let status = qbf_compile_status(&error);
            return (
                BackendObservation {
                    backend: "qbf".to_owned(),
                    engine: qbf_engine(adapter).to_owned(),
                    status,
                    bounded_only: true,
                    independently_checked: false,
                    candidate_sha256: None,
                    resources: resources(elapsed_ms(started), None, None, None, None),
                    solver_result: None,
                    candidate_decision: None,
                    diagnostic: Some(error.to_string()),
                },
                None,
            );
        }
    };
    let qdimacs_sha256 = Some(compilation.qdimacs.metadata.qdimacs_sha256.clone());
    let run = if let Some(adapter) = adapter {
        adapter.run(
            &compilation.qdimacs.document,
            compilation.qdimacs.metadata.bounds,
            config.seed,
            config.solver_timeout,
        )
    } else {
        reference_run(&compilation, config)
    };
    let elapsed = elapsed_ms(started);
    let variables = Some(compilation.qdimacs.metadata.variable_count);
    let clauses = Some(compilation.qdimacs.metadata.clause_count);
    let observation = match run {
        Err(error) => BackendObservation {
            backend: "qbf".to_owned(),
            engine: qbf_engine(adapter).to_owned(),
            status: qbf_solver_error_status(&error),
            bounded_only: true,
            independently_checked: false,
            candidate_sha256: None,
            resources: resources(elapsed, variables, clauses, None, None),
            solver_result: None,
            candidate_decision: None,
            diagnostic: Some(error.to_string()),
        },
        Ok(run) => qbf_observation(run, &compilation, problem, config, elapsed),
    };
    (observation, qdimacs_sha256)
}

fn reference_run(
    compilation: &QbfCompilation,
    config: &BackendComparisonConfig,
) -> Result<QbfSolverRun, crate::qbf_solver::QbfSolverError> {
    let model = evaluate_qbf_reference_model(compilation, config.qbf_truth_variable_limit)
        .map_err(|error| crate::qbf_solver::QbfSolverError::Qdimacs(error.to_string()))?;
    let stdout = if model.truth {
        let assignment = model
            .machine_choice_literals
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        format!("s cnf 1 1 0\nV {assignment} 0\n")
    } else {
        "s cnf 0\n".to_owned()
    };
    let result = if model.truth {
        QbfSolverStatus::Sat
    } else {
        QbfSolverStatus::UnsatAtBound
    };
    let candidate_status = if model.truth {
        QbfCandidateStatus::PendingIndependentCheck
    } else {
        QbfCandidateStatus::NotApplicable
    };
    let empty_hash = sha256(&[]);
    Ok(QbfSolverRun {
        artifact: QbfSolverResultArtifact {
            schema_version: QBF_SOLVER_RESULT_SCHEMA_V1.to_owned(),
            metadata: QbfSolverMetadata {
                solver: "in-process-qbf-reference".to_owned(),
                version: "1".to_owned(),
                platform: std::env::consts::OS.to_owned(),
                source_revision: "in-tree".to_owned(),
                source_sha256: empty_hash.clone(),
                binary_sha256: empty_hash.clone(),
                manifest_sha256: empty_hash.clone(),
                program: "not-applicable".to_owned(),
                argv: Vec::new(),
                timeout_ms: u64::try_from(config.solver_timeout.as_millis()).unwrap_or(u64::MAX),
                seed: config.seed,
                bounds: compilation.qdimacs.metadata.bounds,
            },
            qdimacs_sha256: sha256(compilation.qdimacs.document.as_bytes()),
            stdout_sha256: sha256(stdout.as_bytes()),
            stderr_sha256: empty_hash,
            result,
            candidate_status,
            candidate_accepted: false,
            bounded_only: true,
            diagnostic: None,
        },
        stdout,
        stderr: String::new(),
    })
}

fn qbf_observation(
    run: QbfSolverRun,
    compilation: &QbfCompilation,
    problem: &SynthesisProblem,
    config: &BackendComparisonConfig,
    elapsed: u64,
) -> BackendObservation {
    let solver_status = run.artifact.result;
    let solver_result = run.artifact.clone();
    let (status, independently_checked, candidate_sha256, candidate_decision, diagnostic) =
        if solver_status == QbfSolverStatus::Sat {
            let checked = check_qbf_candidate(&run, compilation, problem, config.checker_limits);
            let accepted = checked.artifact.candidate_accepted;
            let status = if accepted {
                ComparisonStatus::CandidateVerified
            } else {
                ComparisonStatus::MalformedOutput
            };
            let candidate_sha256 = checked.artifact.candidate_sha256.clone();
            let diagnostic = checked
                .artifact
                .diagnostic
                .map(|value| format!("{value:?}"));
            (
                status,
                accepted,
                candidate_sha256,
                Some(checked.artifact),
                diagnostic,
            )
        } else {
            (
                qbf_solver_status(solver_status),
                false,
                None,
                None,
                run.artifact.diagnostic.clone(),
            )
        };
    BackendObservation {
        backend: "qbf".to_owned(),
        engine: run.artifact.metadata.solver.clone(),
        status,
        bounded_only: true,
        independently_checked,
        candidate_sha256,
        resources: resources(
            elapsed,
            Some(compilation.qdimacs.metadata.variable_count),
            Some(compilation.qdimacs.metadata.clause_count),
            None,
            None,
        ),
        solver_result: Some(solver_result),
        candidate_decision,
        diagnostic,
    }
}

fn qbf_compile_status(error: &QbfCompileError) -> ComparisonStatus {
    match error {
        QbfCompileError::DomainLimit { .. }
        | QbfCompileError::ArithmeticOverflow(_)
        | QbfCompileError::TruthVariableLimit { .. } => ComparisonStatus::ResourceExhausted,
        _ => ComparisonStatus::MalformedOutput,
    }
}

fn qbf_solver_error_status(error: &crate::qbf_solver::QbfSolverError) -> ComparisonStatus {
    match error {
        crate::qbf_solver::QbfSolverError::Qdimacs(message)
            if message.contains("truth evaluator variable limit") =>
        {
            ComparisonStatus::ResourceExhausted
        }
        crate::qbf_solver::QbfSolverError::Process(message) if message.contains("TimedOut") => {
            ComparisonStatus::Timeout
        }
        _ => ComparisonStatus::MalformedOutput,
    }
}

fn qbf_solver_status(status: QbfSolverStatus) -> ComparisonStatus {
    match status {
        QbfSolverStatus::Sat => ComparisonStatus::MalformedOutput,
        QbfSolverStatus::UnsatAtBound => ComparisonStatus::UnrealizableWithinBounds,
        QbfSolverStatus::Unknown => ComparisonStatus::SolverUnknown,
        QbfSolverStatus::Timeout => ComparisonStatus::Timeout,
        QbfSolverStatus::Malformed => ComparisonStatus::MalformedOutput,
    }
}

fn qbf_engine(adapter: Option<&QbfSolverAdapter>) -> &'static str {
    if adapter.is_some() {
        "external-qbf"
    } else {
        "in-process-qbf-reference"
    }
}

fn resources(
    wall_time_ms: u64,
    variables: Option<u32>,
    clauses: Option<u32>,
    rounds: Option<u32>,
    stats: Option<&SearchStats>,
) -> ResourceObservation {
    let peak_memory_bytes = process_peak_memory_bytes();
    ResourceObservation {
        wall_time_ms,
        peak_memory_bytes,
        peak_memory_scope: if cfg!(target_os = "linux") {
            "HARNESS_PROCESS_VM_HWM".to_owned()
        } else {
            "NOT_VERIFIED".to_owned()
        },
        variables,
        clauses,
        rounds,
        generated_candidates: stats.map(|value| value.generated_candidates),
        checker_calls: stats.map(|value| value.checker_calls),
    }
}

fn empty_observation(
    backend: &str,
    engine: &str,
    status: ComparisonStatus,
    diagnostic: &str,
) -> BackendObservation {
    BackendObservation {
        backend: backend.to_owned(),
        engine: engine.to_owned(),
        status,
        bounded_only: true,
        independently_checked: false,
        candidate_sha256: None,
        resources: resources(0, None, None, None, None),
        solver_result: None,
        candidate_decision: None,
        diagnostic: Some(diagnostic.to_owned()),
    }
}

fn decision_agreement(left: &BackendObservation, right: &BackendObservation) -> Option<bool> {
    decision(left.status)
        .zip(decision(right.status))
        .map(|(a, b)| a == b)
}

fn decision(status: ComparisonStatus) -> Option<bool> {
    match status {
        ComparisonStatus::CandidateVerified => Some(true),
        ComparisonStatus::UnrealizableWithinBounds => Some(false),
        ComparisonStatus::Timeout
        | ComparisonStatus::ResourceExhausted
        | ComparisonStatus::SolverUnavailable
        | ComparisonStatus::SolverUnknown
        | ComparisonStatus::MalformedOutput
        | ComparisonStatus::NotRun => None,
    }
}

fn candidate_agreement(left: &BackendObservation, right: &BackendObservation) -> Option<bool> {
    left.candidate_sha256
        .as_ref()
        .zip(right.candidate_sha256.as_ref())
        .map(|(a, b)| a == b)
}

fn solver_label(solver: SolverKind) -> String {
    match solver {
        SolverKind::Cvc5 => "cvc5",
        SolverKind::Z3 => "z3",
        SolverKind::Exhaustive => "exhaustive",
    }
    .to_owned()
}

fn machine_sha256(machine: &ReleaseMachine) -> String {
    sha256(&machine.canonical_bytes())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), BackendComparisonError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
