use quotient_seal_engine::HostOutcomeRecord;
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostFault, PublicHostTape};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    evaluate_aets_differential_with_host_tape, AetsAdversarialMatrix, AetsCompiledQsm,
    AetsDifferentialArtifact, AetsDifferentialVerdict, AetsEngineDigests, AetsHostAxis,
    AetsMatrixLimits, AetsPublicSequence, AetsResourceAxis, AetsScenarioAxis,
};

pub const AETS_MATRIX_EXECUTION_VERSION: &str = "noticer-aets-matrix-execution/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AetsHostInjection {
    NotRequested,
    Applied {
        directive_index: u32,
        outcome: HostOutcomeRecord,
    },
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsMatrixCaseArtifact {
    pub case_id_sha256: String,
    pub scenario_axis: String,
    pub host_axis: String,
    pub resource_axis: String,
    pub injection: AetsHostInjection,
    pub verdict: AetsDifferentialVerdict,
    pub differential: AetsDifferentialArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsMatrixExecutionArtifact {
    pub schema_version: String,
    pub evaluator_version: String,
    pub matrix_digest_sha256: String,
    pub matrix_bytes_sha256: String,
    pub hardware_status: String,
    pub verdict: AetsDifferentialVerdict,
    pub match_cases: u32,
    pub counterexample_cases: u32,
    pub unresolved_cases: u32,
    pub cases: Vec<AetsMatrixCaseArtifact>,
}

impl AetsMatrixExecutionArtifact {
    pub fn validate(&self) -> Result<(), AetsMatrixExecutionError> {
        if self.schema_version != AETS_MATRIX_EXECUTION_VERSION
            || self.evaluator_version != AETS_MATRIX_EXECUTION_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.matrix_digest_sha256)
            || !is_sha256(&self.matrix_bytes_sha256)
            || self.cases.is_empty()
        {
            return Err(AetsMatrixExecutionError::ArtifactContract);
        }
        let mut previous = None;
        let mut matched = 0_u32;
        let mut counterexamples = 0_u32;
        let mut unresolved = 0_u32;
        for case in &self.cases {
            if !is_sha256(&case.case_id_sha256)
                || case.scenario_axis.is_empty()
                || case.host_axis.is_empty()
                || case.resource_axis.is_empty()
                || previous.is_some_and(|previous| previous >= case.case_id_sha256.as_str())
            {
                return Err(AetsMatrixExecutionError::ArtifactContract);
            }
            previous = Some(case.case_id_sha256.as_str());
            case.differential
                .validate()
                .map_err(|error| AetsMatrixExecutionError::Differential(error.to_string()))?;
            let expected = if case.injection == AetsHostInjection::NotApplicable {
                AetsDifferentialVerdict::Unresolved
            } else {
                case.differential.verdict
            };
            if expected != case.verdict {
                return Err(AetsMatrixExecutionError::ArtifactContract);
            }
            match case.verdict {
                AetsDifferentialVerdict::Match => matched = checked_increment(matched)?,
                AetsDifferentialVerdict::Counterexample => {
                    counterexamples = checked_increment(counterexamples)?;
                }
                AetsDifferentialVerdict::Unresolved => {
                    unresolved = checked_increment(unresolved)?;
                }
            }
        }
        if self.match_cases != matched
            || self.counterexample_cases != counterexamples
            || self.unresolved_cases != unresolved
            || self.verdict != aggregate_verdict(&self.cases)
        {
            return Err(AetsMatrixExecutionError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AetsMatrixExecutionError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AetsMatrixExecutionError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AetsMatrixExecutionError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn evaluate_aets_adversarial_matrix(
    compiled: &AetsCompiledQsm,
    matrix: &AetsAdversarialMatrix,
    matrix_limits: AetsMatrixLimits,
    engine_digests: &AetsEngineDigests,
) -> Result<AetsMatrixExecutionArtifact, AetsMatrixExecutionError> {
    matrix
        .validate_against(compiled, matrix_limits)
        .map_err(|error| AetsMatrixExecutionError::Matrix(error.to_string()))?;
    let matrix_bytes = matrix
        .canonical_bytes()
        .map_err(|error| AetsMatrixExecutionError::Matrix(error.to_string()))?;
    let mut cases = Vec::with_capacity(matrix.cases().len());
    for case in matrix.cases() {
        let sequence = AetsPublicSequence::new(
            compiled,
            case.commands().to_vec(),
            case.limits(),
            matrix_limits.max_commands_per_case,
        )
        .map_err(|error| AetsMatrixExecutionError::Sequence(error.to_string()))?;
        let (host_tape, injection) = inject_host_axis(case.host(), sequence.host_tape())?;
        let differential = evaluate_aets_differential_with_host_tape(
            compiled,
            &sequence,
            &host_tape,
            engine_digests,
        )
        .map_err(|error| AetsMatrixExecutionError::Differential(error.to_string()))?;
        let verdict = if injection == AetsHostInjection::NotApplicable {
            AetsDifferentialVerdict::Unresolved
        } else {
            differential.verdict
        };
        cases.push(AetsMatrixCaseArtifact {
            case_id_sha256: case.case_id().to_hex(),
            scenario_axis: scenario_name(case.scenario()).to_owned(),
            host_axis: host_name(case.host()).to_owned(),
            resource_axis: resource_name(case.resource()).to_owned(),
            injection,
            verdict,
            differential,
        });
    }
    let match_cases = count_verdict(&cases, AetsDifferentialVerdict::Match)?;
    let counterexample_cases = count_verdict(&cases, AetsDifferentialVerdict::Counterexample)?;
    let unresolved_cases = count_verdict(&cases, AetsDifferentialVerdict::Unresolved)?;
    let artifact = AetsMatrixExecutionArtifact {
        schema_version: AETS_MATRIX_EXECUTION_VERSION.to_owned(),
        evaluator_version: AETS_MATRIX_EXECUTION_VERSION.to_owned(),
        matrix_digest_sha256: matrix.matrix_digest().to_hex(),
        matrix_bytes_sha256: sha256_hex(&matrix_bytes),
        hardware_status: HARDWARE_STATUS.to_owned(),
        verdict: aggregate_verdict(&cases),
        match_cases,
        counterexample_cases,
        unresolved_cases,
        cases,
    };
    artifact.validate()?;
    Ok(artifact)
}

fn inject_host_axis(
    axis: AetsHostAxis,
    base: &PublicHostTape,
) -> Result<(PublicHostTape, AetsHostInjection), AetsMatrixExecutionError> {
    if axis == AetsHostAxis::Continue {
        return Ok((base.clone(), AetsHostInjection::NotRequested));
    }
    let Some(first) = base.directives().first() else {
        return Ok((base.clone(), AetsHostInjection::NotApplicable));
    };
    let outcome = match axis {
        AetsHostAxis::Continue => unreachable!("handled above"),
        AetsHostAxis::Terminate => HostOutcome::Terminate,
        AetsHostAxis::Timeout => HostOutcome::Fault(PublicHostFault::Timeout),
        AetsHostAxis::Reconnect => HostOutcome::Fault(PublicHostFault::Reconnect),
        AetsHostAxis::Loss => HostOutcome::Fault(PublicHostFault::Loss),
    };
    let import = first.import().to_owned();
    let mut directives = base.directives().to_vec();
    directives[0] = HostDirective::new(import, outcome);
    Ok((
        PublicHostTape::new(directives),
        AetsHostInjection::Applied {
            directive_index: 0,
            outcome: HostOutcomeRecord::from(outcome),
        },
    ))
}

fn count_verdict(
    cases: &[AetsMatrixCaseArtifact],
    verdict: AetsDifferentialVerdict,
) -> Result<u32, AetsMatrixExecutionError> {
    u32::try_from(cases.iter().filter(|case| case.verdict == verdict).count())
        .map_err(|_| AetsMatrixExecutionError::Arithmetic)
}

fn checked_increment(value: u32) -> Result<u32, AetsMatrixExecutionError> {
    value
        .checked_add(1)
        .ok_or(AetsMatrixExecutionError::Arithmetic)
}

fn aggregate_verdict(cases: &[AetsMatrixCaseArtifact]) -> AetsDifferentialVerdict {
    if cases
        .iter()
        .any(|case| case.verdict == AetsDifferentialVerdict::Unresolved)
    {
        AetsDifferentialVerdict::Unresolved
    } else if cases
        .iter()
        .any(|case| case.verdict == AetsDifferentialVerdict::Counterexample)
    {
        AetsDifferentialVerdict::Counterexample
    } else {
        AetsDifferentialVerdict::Match
    }
}

const fn scenario_name(axis: AetsScenarioAxis) -> &'static str {
    match axis {
        AetsScenarioAxis::Normal => "NORMAL",
        AetsScenarioAxis::PublicFaultTimeout => "PUBLIC_FAULT_TIMEOUT",
        AetsScenarioAxis::PublicFaultReconnect => "PUBLIC_FAULT_RECONNECT",
        AetsScenarioAxis::PublicFaultLoss => "PUBLIC_FAULT_LOSS",
        AetsScenarioAxis::Reset => "RESET",
        AetsScenarioAxis::Handoff => "HANDOFF",
        AetsScenarioAxis::DeadlineBefore => "DEADLINE_BEFORE",
        AetsScenarioAxis::DeadlineAt => "DEADLINE_AT",
        AetsScenarioAxis::DeadlineAfter => "DEADLINE_AFTER",
        AetsScenarioAxis::UnknownService => "UNKNOWN_SERVICE",
    }
}

const fn host_name(axis: AetsHostAxis) -> &'static str {
    match axis {
        AetsHostAxis::Continue => "CONTINUE",
        AetsHostAxis::Terminate => "TERMINATE",
        AetsHostAxis::Timeout => "TIMEOUT",
        AetsHostAxis::Reconnect => "RECONNECT",
        AetsHostAxis::Loss => "LOSS",
    }
}

const fn resource_name(axis: AetsResourceAxis) -> &'static str {
    match axis {
        AetsResourceAxis::Nominal => "NOMINAL",
        AetsResourceAxis::FuelBoundary => "FUEL_BOUNDARY",
        AetsResourceAxis::MemoryBoundary => "MEMORY_BOUNDARY",
        AetsResourceAxis::HostCallBoundary => "HOST_CALL_BOUNDARY",
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error)]
pub enum AetsMatrixExecutionError {
    #[error("AETS matrix validation failed: {0}")]
    Matrix(String),
    #[error("AETS matrix public sequence failed: {0}")]
    Sequence(String),
    #[error("AETS differential execution failed: {0}")]
    Differential(String),
    #[error("AETS matrix execution artifact serialization failed: {0}")]
    Serialization(String),
    #[error("AETS matrix execution arithmetic overflow")]
    Arithmetic,
    #[error("AETS matrix execution artifact violated its contract")]
    ArtifactContract,
}
