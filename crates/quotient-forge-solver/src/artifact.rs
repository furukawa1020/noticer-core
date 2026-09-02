use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::{OutputStream, RuntimeOutput};

pub const SOLVER_RESULT_SCHEMA_V1: &str = "noticer.quotient_forge.solver_result.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SolverResultKind {
    Sat,
    UnsatAtBound,
    Unknown,
    Timeout,
    Malformed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndependentCheckerResult {
    Accepted,
    Rejected,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SolverRunMetadata {
    pub solver: String,
    pub version: String,
    pub platform: String,
    pub binary_sha256: String,
    pub matrix_sha256: String,
    pub program: String,
    pub argv: Vec<String>,
    pub timeout_ms: u64,
    pub seed: u64,
    pub search_bound: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SolverResultArtifact {
    pub schema_version: String,
    pub metadata: SolverRunMetadata,
    pub query_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub result: SolverResultKind,
    pub independent_checker: IndependentCheckerResult,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Error)]
pub enum SolverArtifactError {
    #[error("solver metadata field is empty: {0}")]
    EmptyMetadata(&'static str),
    #[error("solver metadata hash is not lowercase SHA-256: {0}")]
    InvalidSha256(&'static str),
    #[error("solver timeout must be positive")]
    InvalidTimeout,
    #[error("SAT candidate was rejected by the independent checker")]
    RejectedSatCandidate,
    #[error("SAT candidate was not submitted to the independent checker")]
    UncheckedSatCandidate,
    #[error("independent checker result is only valid for SAT candidates")]
    UnexpectedCheckerResult,
    #[error("UNSAT_AT_BOUND requires an explicit search bound")]
    MissingSearchBound,
    #[error("could not serialize canonical solver artifact: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("could not write canonical solver artifact: {0}")]
    Io(#[from] std::io::Error),
}

impl SolverResultArtifact {
    pub fn from_runtime(
        metadata: SolverRunMetadata,
        query: &str,
        output: RuntimeOutput,
        independent_checker: IndependentCheckerResult,
    ) -> Result<Self, SolverArtifactError> {
        validate_metadata(&metadata)?;
        let (result, stdout, stderr, diagnostic) = decompose_runtime_output(output);

        match (result, independent_checker) {
            (SolverResultKind::Sat, IndependentCheckerResult::Accepted) => {}
            (SolverResultKind::Sat, IndependentCheckerResult::Rejected) => {
                return Err(SolverArtifactError::RejectedSatCandidate);
            }
            (SolverResultKind::Sat, IndependentCheckerResult::NotApplicable) => {
                return Err(SolverArtifactError::UncheckedSatCandidate);
            }
            (_, IndependentCheckerResult::NotApplicable) => {}
            _ => return Err(SolverArtifactError::UnexpectedCheckerResult),
        }

        if result == SolverResultKind::UnsatAtBound && metadata.search_bound.trim().is_empty() {
            return Err(SolverArtifactError::MissingSearchBound);
        }

        Ok(Self {
            schema_version: SOLVER_RESULT_SCHEMA_V1.to_owned(),
            metadata,
            query_sha256: sha256(query.as_bytes()),
            stdout_sha256: sha256(stdout.as_bytes()),
            stderr_sha256: sha256(stderr.as_bytes()),
            result,
            independent_checker,
            diagnostic,
        })
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, SolverArtifactError> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn digest_sha256(&self) -> Result<String, SolverArtifactError> {
        Ok(sha256(&self.canonical_json_bytes()?))
    }

    pub fn write_canonical(&self, path: &Path) -> Result<(), SolverArtifactError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.canonical_json_bytes()?)?;
        Ok(())
    }
}

pub fn classify_runtime_output(output: &RuntimeOutput) -> SolverResultKind {
    match output {
        RuntimeOutput::Completed {
            stdout, success, ..
        } if *success => match stdout.lines().map(str::trim).find(|line| !line.is_empty()) {
            Some("sat") => SolverResultKind::Sat,
            Some("unsat") => SolverResultKind::UnsatAtBound,
            Some("unknown") => SolverResultKind::Unknown,
            _ => SolverResultKind::Malformed,
        },
        RuntimeOutput::TimedOut => SolverResultKind::Timeout,
        RuntimeOutput::Completed { .. } | RuntimeOutput::OutputLimitExceeded { .. } => {
            SolverResultKind::Malformed
        }
    }
}

fn decompose_runtime_output(
    output: RuntimeOutput,
) -> (SolverResultKind, String, String, Option<String>) {
    let result = classify_runtime_output(&output);
    match output {
        RuntimeOutput::Completed {
            stdout,
            stderr,
            success,
        } => {
            let diagnostic = if success && result != SolverResultKind::Malformed {
                None
            } else if success {
                Some("UNRECOGNIZED_SOLVER_OUTPUT".to_owned())
            } else {
                Some("PROCESS_EXIT_NONZERO".to_owned())
            };
            (result, stdout, stderr, diagnostic)
        }
        RuntimeOutput::TimedOut => (
            result,
            String::new(),
            String::new(),
            Some("PROCESS_TIMEOUT".to_owned()),
        ),
        RuntimeOutput::OutputLimitExceeded { stream } => {
            let diagnostic = match stream {
                OutputStream::Stdout => "OUTPUT_LIMIT_STDOUT",
                OutputStream::Stderr => "OUTPUT_LIMIT_STDERR",
            };
            (
                result,
                String::new(),
                String::new(),
                Some(diagnostic.to_owned()),
            )
        }
    }
}

fn validate_metadata(metadata: &SolverRunMetadata) -> Result<(), SolverArtifactError> {
    for (name, value) in [
        ("solver", metadata.solver.as_str()),
        ("version", metadata.version.as_str()),
        ("platform", metadata.platform.as_str()),
        ("program", metadata.program.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(SolverArtifactError::EmptyMetadata(name));
        }
    }
    if metadata.argv.is_empty()
        || metadata
            .argv
            .iter()
            .any(|arg| arg.bytes().any(|byte| matches!(byte, b'\r' | b'\n')))
    {
        return Err(SolverArtifactError::EmptyMetadata("argv"));
    }
    if !is_lower_sha256(&metadata.binary_sha256) {
        return Err(SolverArtifactError::InvalidSha256("binary_sha256"));
    }
    if !is_lower_sha256(&metadata.matrix_sha256) {
        return Err(SolverArtifactError::InvalidSha256("matrix_sha256"));
    }
    if metadata.timeout_ms == 0 {
        return Err(SolverArtifactError::InvalidTimeout);
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
