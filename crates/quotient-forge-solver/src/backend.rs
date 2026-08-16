use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use quotient_forge_check::{check, CheckOutcome, CounterexampleKind};
use quotient_forge_synth::{
    blocking_clause_from_counterexample, find_feasible, optimize_cost, MachineCell, ProblemError,
    ReleaseMachine, SynthesisLimits, SynthesisOutcome, SynthesisProblem,
};

use crate::parser::{parse_solver_output, ParsedSolverOutput};
use crate::smtlib::{
    encode_smtlib, expected_variable_names, ConstraintKind, HardBlocker, ObjectiveCost,
    SmtEncoding, SmtEncodingError, SmtPhase,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SolverKind {
    Cvc5,
    Z3,
    Exhaustive,
}

impl SolverKind {
    const fn program(self) -> &'static str {
        match self {
            Self::Cvc5 => "cvc5",
            Self::Z3 => "z3",
            Self::Exhaustive => "quotient-forge-exhaustive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolverSelection {
    Auto,
    Explicit(SolverKind),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    NotInstalled,
    Io(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeOutput {
    Completed {
        stdout: String,
        stderr: String,
        success: bool,
    },
    TimedOut,
}

pub trait SolverRuntime {
    fn version(&self, solver: SolverKind) -> Result<String, RuntimeError>;

    fn run(
        &self,
        solver: SolverKind,
        script: &str,
        timeout: Duration,
    ) -> Result<RuntimeOutput, RuntimeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StandardRuntime;

impl SolverRuntime for StandardRuntime {
    fn version(&self, solver: SolverKind) -> Result<String, RuntimeError> {
        if solver == SolverKind::Exhaustive {
            return Ok(env!("CARGO_PKG_VERSION").to_owned());
        }
        let arguments: &[&str] = match solver {
            SolverKind::Cvc5 => &["--version"],
            SolverKind::Z3 => &["-version"],
            SolverKind::Exhaustive => &[],
        };
        let output = Command::new(solver.program())
            .args(arguments)
            .output()
            .map_err(runtime_io)?;
        if !output.status.success() {
            return Err(RuntimeError::Io(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned())
    }

    fn run(
        &self,
        solver: SolverKind,
        script: &str,
        timeout: Duration,
    ) -> Result<RuntimeOutput, RuntimeError> {
        let arguments: &[&str] = match solver {
            SolverKind::Cvc5 => &["--lang=smt2", "--produce-models"],
            SolverKind::Z3 => &["-in", "-smt2"],
            SolverKind::Exhaustive => {
                return Err(RuntimeError::Io(
                    "exhaustive backend does not execute a process".to_owned(),
                ));
            }
        };
        let mut child = Command::new(solver.program())
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(runtime_io)?;
        child
            .stdin
            .take()
            .ok_or_else(|| RuntimeError::Io("solver stdin unavailable".to_owned()))?
            .write_all(script.as_bytes())
            .map_err(runtime_io)?;

        let started = Instant::now();
        loop {
            if child.try_wait().map_err(runtime_io)?.is_some() {
                let output = child.wait_with_output().map_err(runtime_io)?;
                return Ok(RuntimeOutput::Completed {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    success: output.status.success(),
                });
            }
            if started.elapsed() >= timeout {
                child.kill().map_err(runtime_io)?;
                let _ = child.wait();
                return Ok(RuntimeOutput::TimedOut);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn runtime_io(error: std::io::Error) -> RuntimeError {
    if error.kind() == ErrorKind::NotFound {
        RuntimeError::NotInstalled
    } else {
        RuntimeError::Io(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectionRecord {
    pub solver: SolverKind,
    pub program: String,
    pub available: bool,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseArtifact {
    pub phase: SmtPhase,
    pub canonical_smtlib: String,
    pub raw_output: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolverArtifact {
    pub requested: SolverSelection,
    pub selected: Option<SolverKind>,
    pub detection_order: Vec<DetectionRecord>,
    pub selected_version: Option<String>,
    pub phases: Vec<PhaseArtifact>,
    pub cegis_rounds: u32,
    pub hard_blockers: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendStatus {
    Sat,
    Unsat,
    Timeout,
    MalformedOutput,
    NotInstalled,
    ResourceExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendResult {
    pub status: BackendStatus,
    pub machine: Option<ReleaseMachine>,
    pub artifact: SolverArtifact,
    pub detail: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BackendConfig {
    pub selection: SolverSelection,
    pub state_bound: u32,
    pub optimize: bool,
    pub output_costs: Vec<ObjectiveCost>,
    pub solver_timeout: Duration,
    pub max_cegis_rounds: u32,
    pub exhaustive_fallback_max_cells: usize,
    pub exhaustive_limits: SynthesisLimits,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            selection: SolverSelection::Auto,
            state_bound: 2,
            optimize: false,
            output_costs: Vec::new(),
            solver_timeout: Duration::from_secs(30),
            max_cegis_rounds: 10_000,
            exhaustive_fallback_max_cells: 16,
            exhaustive_limits: SynthesisLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendError {
    Problem(ProblemError),
    Encoding(SmtEncodingError),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "solver backend error: {self:?}")
    }
}

impl std::error::Error for BackendError {}

impl From<ProblemError> for BackendError {
    fn from(error: ProblemError) -> Self {
        Self::Problem(error)
    }
}

impl From<SmtEncodingError> for BackendError {
    fn from(error: SmtEncodingError) -> Self {
        Self::Encoding(error)
    }
}

pub fn solve(
    problem: &SynthesisProblem,
    config: &BackendConfig,
    runtime: &dyn SolverRuntime,
) -> Result<BackendResult, BackendError> {
    problem.validate()?;
    let (selected, detections) = select_solver(config.selection, runtime);
    let mut artifact = SolverArtifact {
        requested: config.selection,
        selected,
        selected_version: selected.and_then(|solver| {
            detections
                .iter()
                .find(|record| record.solver == solver)
                .and_then(|record| record.version.clone())
        }),
        detection_order: detections,
        phases: Vec::new(),
        cegis_rounds: 0,
        hard_blockers: 0,
    };

    match selected {
        Some(SolverKind::Exhaustive) => run_exhaustive(problem, config, artifact),
        Some(solver @ (SolverKind::Cvc5 | SolverKind::Z3)) => {
            run_external(problem, config, runtime, solver, artifact)
        }
        None => {
            let cells = usize_index(config.state_bound)
                .saturating_mul(usize_index(problem.machine_symbol_count));
            if config.selection == SolverSelection::Auto
                && cells <= config.exhaustive_fallback_max_cells
            {
                artifact.selected = Some(SolverKind::Exhaustive);
                artifact.selected_version = Some(env!("CARGO_PKG_VERSION").to_owned());
                artifact.detection_order.push(DetectionRecord {
                    solver: SolverKind::Exhaustive,
                    program: SolverKind::Exhaustive.program().to_owned(),
                    available: true,
                    version: artifact.selected_version.clone(),
                    error: None,
                });
                run_exhaustive(problem, config, artifact)
            } else {
                Ok(result(
                    BackendStatus::NotInstalled,
                    None,
                    artifact,
                    "requested solver is not installed and exhaustive fallback is not allowed",
                ))
            }
        }
    }
}

fn select_solver(
    selection: SolverSelection,
    runtime: &dyn SolverRuntime,
) -> (Option<SolverKind>, Vec<DetectionRecord>) {
    if let SolverSelection::Explicit(SolverKind::Exhaustive) = selection {
        return (
            Some(SolverKind::Exhaustive),
            vec![DetectionRecord {
                solver: SolverKind::Exhaustive,
                program: SolverKind::Exhaustive.program().to_owned(),
                available: true,
                version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                error: None,
            }],
        );
    }
    let order: Vec<_> = match selection {
        SolverSelection::Auto => vec![SolverKind::Cvc5, SolverKind::Z3],
        SolverSelection::Explicit(solver) => vec![solver],
    };
    let mut records = Vec::new();
    for solver in order {
        match runtime.version(solver) {
            Ok(version) => records.push(DetectionRecord {
                solver,
                program: solver.program().to_owned(),
                available: true,
                version: Some(version),
                error: None,
            }),
            Err(error) => records.push(DetectionRecord {
                solver,
                program: solver.program().to_owned(),
                available: false,
                version: None,
                error: Some(format!("{error:?}")),
            }),
        }
    }
    let selected = records
        .iter()
        .find(|record| record.available)
        .map(|record| record.solver);
    (selected, records)
}

fn run_exhaustive(
    problem: &SynthesisProblem,
    config: &BackendConfig,
    artifact: SolverArtifact,
) -> Result<BackendResult, BackendError> {
    let limits = SynthesisLimits {
        max_states: config.state_bound,
        ..config.exhaustive_limits
    };
    let outcome = if config.optimize {
        optimize_cost(problem, limits)
    } else {
        find_feasible(problem, limits)
    };
    match outcome {
        Ok(SynthesisOutcome::Realizable(report)) => Ok(BackendResult {
            status: BackendStatus::Sat,
            machine: Some(report.machine),
            artifact,
            detail: None,
        }),
        Ok(SynthesisOutcome::Unrealizable(_)) => Ok(BackendResult {
            status: BackendStatus::Unsat,
            machine: None,
            artifact,
            detail: None,
        }),
        Ok(SynthesisOutcome::Inconclusive { reason, .. }) => {
            let status = if matches!(
                reason,
                quotient_forge_synth::InconclusiveReason::TimeLimit { .. }
            ) {
                BackendStatus::Timeout
            } else {
                BackendStatus::ResourceExhausted
            };
            Ok(result(
                status,
                None,
                artifact,
                &format!("exhaustive backend was inconclusive: {reason:?}"),
            ))
        }
        Err(error) => Ok(result(
            BackendStatus::MalformedOutput,
            None,
            artifact,
            &format!("exhaustive backend failed: {error}"),
        )),
    }
}

fn run_external(
    problem: &SynthesisProblem,
    config: &BackendConfig,
    runtime: &dyn SolverRuntime,
    solver: SolverKind,
    mut artifact: SolverArtifact,
) -> Result<BackendResult, BackendError> {
    let output_costs = if config.output_costs.is_empty() {
        derive_output_costs(problem)
    } else {
        config.output_costs.clone()
    };
    let mut blockers = Vec::new();
    let mut phase = SmtPhase::Feasibility;

    for round in 0..config.max_cegis_rounds {
        artifact.cegis_rounds = round + 1;
        let encoding = SmtEncoding {
            state_count: config.state_bound,
            symbol_count: problem.machine_symbol_count,
            output_count: u32::try_from(problem.outputs.len()).unwrap_or(u32::MAX),
            blockers: blockers.clone(),
            phase,
            output_costs: output_costs.clone(),
        };
        let script = encode_smtlib(&encoding)?;
        let runtime_output = match runtime.run(solver, &script, config.solver_timeout) {
            Ok(output) => output,
            Err(RuntimeError::NotInstalled) => {
                return Ok(result(
                    BackendStatus::NotInstalled,
                    None,
                    artifact,
                    "solver disappeared after detection",
                ));
            }
            Err(RuntimeError::Io(error)) => {
                return Ok(result(
                    BackendStatus::MalformedOutput,
                    None,
                    artifact,
                    &error,
                ));
            }
        };
        let RuntimeOutput::Completed {
            stdout,
            stderr,
            success,
        } = runtime_output
        else {
            artifact.phases.push(PhaseArtifact {
                phase,
                canonical_smtlib: script,
                raw_output: None,
            });
            return Ok(result(
                BackendStatus::Timeout,
                None,
                artifact,
                "solver process exceeded its timeout",
            ));
        };
        artifact.phases.push(PhaseArtifact {
            phase,
            canonical_smtlib: script,
            raw_output: Some(stdout.clone()),
        });
        if !success && stdout.trim().is_empty() {
            return Ok(result(
                BackendStatus::MalformedOutput,
                None,
                artifact,
                &format!("solver exited unsuccessfully: {stderr}"),
            ));
        }

        let expected = expected_variable_names(config.state_bound, problem.machine_symbol_count);
        match parse_solver_output(&stdout, &expected) {
            Ok(ParsedSolverOutput::Unsat) if phase == SmtPhase::Feasibility => {
                artifact.hard_blockers = blockers.len();
                return Ok(BackendResult {
                    status: BackendStatus::Unsat,
                    machine: None,
                    artifact,
                    detail: None,
                });
            }
            Ok(ParsedSolverOutput::Unsat) => {
                return Ok(result(
                    BackendStatus::MalformedOutput,
                    None,
                    artifact,
                    "optimization became unsat after a feasible model",
                ));
            }
            Ok(ParsedSolverOutput::Unknown(reason)) => {
                let timeout = reason
                    .as_deref()
                    .is_some_and(|value| value.contains("timeout"));
                return Ok(result(
                    if timeout {
                        BackendStatus::Timeout
                    } else {
                        BackendStatus::MalformedOutput
                    },
                    None,
                    artifact,
                    reason.as_deref().unwrap_or("solver returned unknown"),
                ));
            }
            Ok(ParsedSolverOutput::Sat(model)) => {
                let Some(machine) = decode_machine(
                    &model,
                    config.state_bound,
                    problem.machine_symbol_count,
                    problem.outputs.len(),
                ) else {
                    return Ok(result(
                        BackendStatus::MalformedOutput,
                        None,
                        artifact,
                        "solver model violates declared variable bounds or symmetry",
                    ));
                };
                let checker_model = match problem.lower_candidate(&machine) {
                    Ok(model) => model,
                    Err(error) => {
                        return Ok(result(
                            BackendStatus::MalformedOutput,
                            None,
                            artifact,
                            &format!("solver candidate cannot be lowered: {error}"),
                        ));
                    }
                };
                match check(&checker_model, config.exhaustive_limits.checker_limits) {
                    Ok(CheckOutcome::Verified(_))
                        if config.optimize && phase == SmtPhase::Feasibility =>
                    {
                        phase = SmtPhase::Optimization;
                    }
                    Ok(CheckOutcome::Verified(_)) => {
                        artifact.hard_blockers = blockers.len();
                        return Ok(BackendResult {
                            status: BackendStatus::Sat,
                            machine: Some(machine),
                            artifact,
                            detail: None,
                        });
                    }
                    Ok(CheckOutcome::Counterexample(counterexample)) => {
                        let Some(clause) =
                            blocking_clause_from_counterexample(problem, &machine, &counterexample)
                        else {
                            return Ok(result(
                                BackendStatus::MalformedOutput,
                                None,
                                artifact,
                                "checker counterexample could not be lowered to SMT blocker",
                            ));
                        };
                        if !clause.blocks(&machine) {
                            return Ok(result(
                                BackendStatus::MalformedOutput,
                                None,
                                artifact,
                                "checker blocker does not exclude source model",
                            ));
                        }
                        blockers.push(HardBlocker {
                            kind: constraint_kind(&counterexample.kind),
                            clause,
                        });
                        artifact.hard_blockers = blockers.len();
                    }
                    Ok(CheckOutcome::Inconclusive(_)) => {
                        return Ok(result(
                            BackendStatus::ResourceExhausted,
                            None,
                            artifact,
                            "independent checker exhausted resources",
                        ));
                    }
                    Err(error) => {
                        return Ok(result(
                            BackendStatus::MalformedOutput,
                            None,
                            artifact,
                            &format!("independent checker rejected model: {error}"),
                        ));
                    }
                }
            }
            Err(error) => {
                return Ok(result(
                    BackendStatus::MalformedOutput,
                    None,
                    artifact,
                    &error.to_string(),
                ));
            }
        }
    }
    artifact.hard_blockers = blockers.len();
    Ok(result(
        BackendStatus::ResourceExhausted,
        None,
        artifact,
        "CEGIS round limit reached",
    ))
}

fn decode_machine(
    model: &std::collections::BTreeMap<String, i64>,
    state_count: u32,
    symbol_count: u32,
    output_count: usize,
) -> Option<ReleaseMachine> {
    let mut cells =
        Vec::with_capacity(usize_index(state_count).saturating_mul(usize_index(symbol_count)));
    for state in 0..state_count {
        for symbol in 0..symbol_count {
            let next = u32::try_from(*model.get(&format!("n_{state}_{symbol}"))?).ok()?;
            let output = u32::try_from(*model.get(&format!("o_{state}_{symbol}"))?).ok()?;
            cells.push(MachineCell {
                next_state: next,
                output,
            });
        }
    }
    let machine = ReleaseMachine {
        state_count,
        symbol_count,
        cells,
    };
    machine.validate(symbol_count, output_count).ok()?;
    Some(machine)
}

fn constraint_kind(kind: &CounterexampleKind) -> ConstraintKind {
    match kind {
        CounterexampleKind::SecurityDivergence => ConstraintKind::Security,
        CounterexampleKind::RecoverableFaultViolation { .. } => ConstraintKind::Fault,
        CounterexampleKind::UnauthorizedAction { .. }
        | CounterexampleKind::DuplicateAction { .. }
        | CounterexampleKind::MissedDeadline { .. } => ConstraintKind::Utility,
    }
}

fn derive_output_costs(problem: &SynthesisProblem) -> Vec<ObjectiveCost> {
    problem
        .outputs
        .iter()
        .map(|output| ObjectiveCost {
            dummy: u64::from(
                output.emitted && output.fields.is_empty() && output.actions.is_empty(),
            ),
            latency: 0,
            retry: 0,
            reconnect: 0,
        })
        .collect()
}

fn result(
    status: BackendStatus,
    machine: Option<ReleaseMachine>,
    artifact: SolverArtifact,
    detail: &str,
) -> BackendResult {
    BackendResult {
        status,
        machine,
        artifact,
        detail: Some(detail.to_owned()),
    }
}

fn usize_index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}
