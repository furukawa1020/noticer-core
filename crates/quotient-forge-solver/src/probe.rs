use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::sha256;
use crate::backend::{OutputStream, RuntimeOutput, SolverKind, SolverRuntime};

pub const SOLVER_PROBE_SCHEMA_V1: &str = "noticer.quotient_forge.solver_probe.v1";

const INTEGER_MODEL_PROBE: &str = "(set-option :produce-models true)\n(set-logic QF_LIA)\n(declare-const probe_x Int)\n(assert (= probe_x 7))\n(check-sat)\n(get-value (probe_x))\n(exit)\n";
const OPTIMIZATION_PROBE: &str = "(set-option :produce-models true)\n(set-logic QF_LIA)\n(declare-const probe_opt Int)\n(assert (>= probe_opt 0))\n(minimize probe_opt)\n(check-sat)\n(get-value (probe_opt))\n(exit)\n";
const REASON_UNKNOWN_PROBE: &str =
    "(set-logic QF_LIA)\n(check-sat)\n(get-info :reason-unknown)\n(exit)\n";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SolverCapability {
    IntegerModel,
    Optimization,
    ReasonUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityProbeStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProbeCheck {
    pub capability: SolverCapability,
    pub input_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub status: CapabilityProbeStatus,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProbeArtifact {
    pub schema_version: String,
    pub solver: String,
    pub timeout_ms: u64,
    pub available: bool,
    pub checks: Vec<CapabilityProbeCheck>,
}

#[derive(Debug, Error)]
pub enum CapabilityProbeArtifactError {
    #[error("could not serialize canonical capability probe: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("could not write canonical capability probe: {0}")]
    Io(#[from] std::io::Error),
}

impl CapabilityProbeArtifact {
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, CapabilityProbeArtifactError> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn digest_sha256(&self) -> Result<String, CapabilityProbeArtifactError> {
        Ok(sha256(&self.canonical_json_bytes()?))
    }

    pub fn write_canonical(&self, path: &Path) -> Result<(), CapabilityProbeArtifactError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.canonical_json_bytes()?)?;
        Ok(())
    }
}

pub fn run_capability_probe<R: SolverRuntime + ?Sized>(
    runtime: &R,
    solver: SolverKind,
    timeout: Duration,
) -> CapabilityProbeArtifact {
    let cases = [
        (
            SolverCapability::IntegerModel,
            INTEGER_MODEL_PROBE,
            ProbeExpectation::IntegerBinding {
                name: "probe_x",
                value: "7",
            },
        ),
        (
            SolverCapability::Optimization,
            OPTIMIZATION_PROBE,
            ProbeExpectation::IntegerBinding {
                name: "probe_opt",
                value: "0",
            },
        ),
        (
            SolverCapability::ReasonUnknown,
            REASON_UNKNOWN_PROBE,
            ProbeExpectation::ReasonUnknown,
        ),
    ];
    let checks = cases
        .into_iter()
        .map(|(capability, script, expectation)| {
            execute_probe(runtime, solver, timeout, capability, script, expectation)
        })
        .collect::<Vec<_>>();
    let available = checks
        .iter()
        .all(|check| check.status == CapabilityProbeStatus::Passed);

    CapabilityProbeArtifact {
        schema_version: SOLVER_PROBE_SCHEMA_V1.to_owned(),
        solver: solver_name(solver).to_owned(),
        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
        available,
        checks,
    }
}

#[derive(Clone, Copy)]
enum ProbeExpectation {
    IntegerBinding {
        name: &'static str,
        value: &'static str,
    },
    ReasonUnknown,
}

fn execute_probe<R: SolverRuntime + ?Sized>(
    runtime: &R,
    solver: SolverKind,
    timeout: Duration,
    capability: SolverCapability,
    script: &str,
    expectation: ProbeExpectation,
) -> CapabilityProbeCheck {
    let mut check = CapabilityProbeCheck {
        capability,
        input_sha256: sha256(script.as_bytes()),
        stdout_sha256: sha256(&[]),
        stderr_sha256: sha256(&[]),
        status: CapabilityProbeStatus::Failed,
        diagnostic: Some("RUNTIME_ERROR".to_owned()),
    };

    match runtime.run(solver, script, timeout) {
        Ok(RuntimeOutput::Completed {
            stdout,
            stderr,
            success,
        }) => {
            check.stdout_sha256 = sha256(stdout.as_bytes());
            check.stderr_sha256 = sha256(stderr.as_bytes());
            if !success {
                check.diagnostic = Some("PROCESS_EXIT_NONZERO".to_owned());
            } else if expectation_matches(expectation, &stdout) {
                check.status = CapabilityProbeStatus::Passed;
                check.diagnostic = None;
            } else {
                check.diagnostic = Some("UNEXPECTED_PROBE_OUTPUT".to_owned());
            }
        }
        Ok(RuntimeOutput::TimedOut) => {
            check.diagnostic = Some("PROCESS_TIMEOUT".to_owned());
        }
        Ok(RuntimeOutput::OutputLimitExceeded { stream }) => {
            check.diagnostic = Some(
                match stream {
                    OutputStream::Stdout => "OUTPUT_LIMIT_STDOUT",
                    OutputStream::Stderr => "OUTPUT_LIMIT_STDERR",
                }
                .to_owned(),
            );
        }
        Err(_) => {}
    }
    check
}

fn expectation_matches(expectation: ProbeExpectation, stdout: &str) -> bool {
    let has_sat = stdout.lines().any(|line| line.trim() == "sat");
    if !has_sat {
        return false;
    }
    match expectation {
        ProbeExpectation::IntegerBinding { name, value } => {
            let tokens = stdout
                .split(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
                })
                .filter(|token| !token.is_empty())
                .collect::<Vec<_>>();
            tokens
                .windows(2)
                .any(|pair| pair[0] == name && pair[1] == value)
        }
        ProbeExpectation::ReasonUnknown => stdout.contains(":reason-unknown"),
    }
}

fn solver_name(solver: SolverKind) -> &'static str {
    match solver {
        SolverKind::Cvc5 => "cvc5",
        SolverKind::Z3 => "z3",
        SolverKind::Exhaustive => "exhaustive",
    }
}
