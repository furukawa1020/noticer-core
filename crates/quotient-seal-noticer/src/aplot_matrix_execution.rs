use quotient_seal_engine::HostOutcomeRecord;
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostFault, PublicHostTape};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    evaluate_aplot_differential_with_host_tape, AplotAdversarialMatrix, AplotCompiledQsm,
    AplotDifferentialArtifact, AplotDifferentialVerdict, AplotEngineDigests, AplotHostAxis,
    AplotMatrixLimits, AplotPublicSequence, AplotResourceAxis, AplotScenarioAxis,
};

pub const APLOT_MATRIX_EXECUTION_VERSION: &str = "noticer-aplot-matrix-execution/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AplotHostInjection {
    NotRequested,
    Applied {
        directive_index: u32,
        outcome: HostOutcomeRecord,
    },
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AplotMatrixCaseArtifact {
    pub case_id_sha256: String,
    pub scenario_axis: String,
    pub host_axis: String,
    pub resource_axis: String,
    pub injection: AplotHostInjection,
    pub verdict: AplotDifferentialVerdict,
    pub differential: AplotDifferentialArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AplotMatrixExecutionArtifact {
    pub schema_version: String,
    pub evaluator_version: String,
    pub matrix_digest_sha256: String,
    pub matrix_bytes_sha256: String,
    pub hardware_status: String,
    pub verdict: AplotDifferentialVerdict,
    pub match_cases: u32,
    pub counterexample_cases: u32,
    pub unresolved_cases: u32,
    pub cases: Vec<AplotMatrixCaseArtifact>,
}

impl AplotMatrixExecutionArtifact {
    pub fn validate(&self) -> Result<(), AplotMatrixExecutionError> {
        if self.schema_version != APLOT_MATRIX_EXECUTION_VERSION
            || self.evaluator_version != APLOT_MATRIX_EXECUTION_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.matrix_digest_sha256)
            || !is_sha256(&self.matrix_bytes_sha256)
            || self.cases.is_empty()
        {
            return Err(AplotMatrixExecutionError::ArtifactContract);
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
                return Err(AplotMatrixExecutionError::ArtifactContract);
            }
            previous = Some(case.case_id_sha256.as_str());
            case.differential
                .validate()
                .map_err(|error| AplotMatrixExecutionError::Differential(error.to_string()))?;
            let expected = if case.injection == AplotHostInjection::NotApplicable {
                AplotDifferentialVerdict::Unresolved
            } else {
                case.differential.verdict
            };
            if expected != case.verdict {
                return Err(AplotMatrixExecutionError::ArtifactContract);
            }
            match case.verdict {
                AplotDifferentialVerdict::Match => matched = checked_increment(matched)?,
                AplotDifferentialVerdict::Counterexample => {
                    counterexamples = checked_increment(counterexamples)?;
                }
                AplotDifferentialVerdict::Unresolved => {
                    unresolved = checked_increment(unresolved)?;
                }
            }
        }
        if self.match_cases != matched
            || self.counterexample_cases != counterexamples
            || self.unresolved_cases != unresolved
            || self.verdict != aggregate_verdict(&self.cases)
        {
            return Err(AplotMatrixExecutionError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AplotMatrixExecutionError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AplotMatrixExecutionError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AplotMatrixExecutionError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn evaluate_aplot_adversarial_matrix(
    compiled: &AplotCompiledQsm,
    matrix: &AplotAdversarialMatrix,
    matrix_limits: AplotMatrixLimits,
    engine_digests: &AplotEngineDigests,
) -> Result<AplotMatrixExecutionArtifact, AplotMatrixExecutionError> {
    matrix
        .validate_against(compiled, matrix_limits)
        .map_err(|error| AplotMatrixExecutionError::Matrix(error.to_string()))?;
    let matrix_bytes = matrix
        .canonical_bytes()
        .map_err(|error| AplotMatrixExecutionError::Matrix(error.to_string()))?;
    let mut cases = Vec::with_capacity(matrix.cases().len());
    for case in matrix.cases() {
        let sequence = AplotPublicSequence::new(
            compiled,
            case.commands().to_vec(),
            case.limits(),
            matrix_limits.max_commands_per_case,
        )
        .map_err(|error| AplotMatrixExecutionError::Sequence(error.to_string()))?;
        let (host_tape, injection) = inject_host_axis(case.host(), sequence.host_tape())?;
        let differential = evaluate_aplot_differential_with_host_tape(
            compiled,
            &sequence,
            &host_tape,
            engine_digests,
        )
        .map_err(|error| AplotMatrixExecutionError::Differential(error.to_string()))?;
        let verdict = if injection == AplotHostInjection::NotApplicable {
            AplotDifferentialVerdict::Unresolved
        } else {
            differential.verdict
        };
        cases.push(AplotMatrixCaseArtifact {
            case_id_sha256: case.case_id().to_hex(),
            scenario_axis: scenario_name(case.scenario()).to_owned(),
            host_axis: host_name(case.host()).to_owned(),
            resource_axis: resource_name(case.resource()).to_owned(),
            injection,
            verdict,
            differential,
        });
    }
    let match_cases = count_verdict(&cases, AplotDifferentialVerdict::Match)?;
    let counterexample_cases = count_verdict(&cases, AplotDifferentialVerdict::Counterexample)?;
    let unresolved_cases = count_verdict(&cases, AplotDifferentialVerdict::Unresolved)?;
    let artifact = AplotMatrixExecutionArtifact {
        schema_version: APLOT_MATRIX_EXECUTION_VERSION.to_owned(),
        evaluator_version: APLOT_MATRIX_EXECUTION_VERSION.to_owned(),
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
    axis: AplotHostAxis,
    base: &PublicHostTape,
) -> Result<(PublicHostTape, AplotHostInjection), AplotMatrixExecutionError> {
    if axis == AplotHostAxis::Continue {
        return Ok((base.clone(), AplotHostInjection::NotRequested));
    }
    let Some(first) = base.directives().first() else {
        return Ok((base.clone(), AplotHostInjection::NotApplicable));
    };
    let outcome = match axis {
        AplotHostAxis::Continue => unreachable!("handled above"),
        AplotHostAxis::Terminate => HostOutcome::Terminate,
        AplotHostAxis::Timeout => HostOutcome::Fault(PublicHostFault::Timeout),
        AplotHostAxis::Reconnect => HostOutcome::Fault(PublicHostFault::Reconnect),
        AplotHostAxis::Loss => HostOutcome::Fault(PublicHostFault::Loss),
    };
    let import = first.import().to_owned();
    let mut directives = base.directives().to_vec();
    directives[0] = HostDirective::new(import, outcome);
    Ok((
        PublicHostTape::new(directives),
        AplotHostInjection::Applied {
            directive_index: 0,
            outcome: HostOutcomeRecord::from(outcome),
        },
    ))
}

fn count_verdict(
    cases: &[AplotMatrixCaseArtifact],
    verdict: AplotDifferentialVerdict,
) -> Result<u32, AplotMatrixExecutionError> {
    u32::try_from(cases.iter().filter(|case| case.verdict == verdict).count())
        .map_err(|_| AplotMatrixExecutionError::Arithmetic)
}

fn checked_increment(value: u32) -> Result<u32, AplotMatrixExecutionError> {
    value
        .checked_add(1)
        .ok_or(AplotMatrixExecutionError::Arithmetic)
}

fn aggregate_verdict(cases: &[AplotMatrixCaseArtifact]) -> AplotDifferentialVerdict {
    if cases
        .iter()
        .any(|case| case.verdict == AplotDifferentialVerdict::Unresolved)
    {
        AplotDifferentialVerdict::Unresolved
    } else if cases
        .iter()
        .any(|case| case.verdict == AplotDifferentialVerdict::Counterexample)
    {
        AplotDifferentialVerdict::Counterexample
    } else {
        AplotDifferentialVerdict::Match
    }
}

const fn scenario_name(axis: AplotScenarioAxis) -> &'static str {
    match axis {
        AplotScenarioAxis::Normal => "NORMAL",
        AplotScenarioAxis::DeclaredLoss => "DECLARED_LOSS",
        AplotScenarioAxis::DeclaredReconnect => "DECLARED_RECONNECT",
        AplotScenarioAxis::PublicFaultTimeout => "PUBLIC_FAULT_TIMEOUT",
        AplotScenarioAxis::PublicFaultReconnect => "PUBLIC_FAULT_RECONNECT",
        AplotScenarioAxis::PublicFaultLoss => "PUBLIC_FAULT_LOSS",
        AplotScenarioAxis::DuplicateStep => "DUPLICATE_STEP",
        AplotScenarioAxis::CapacityBoundary => "CAPACITY_BOUNDARY",
        AplotScenarioAxis::SecretRetryAttempt => "SECRET_RETRY_ATTEMPT",
        AplotScenarioAxis::Reset => "RESET",
        AplotScenarioAxis::Handoff => "HANDOFF",
        AplotScenarioAxis::DeadlineBefore => "DEADLINE_BEFORE",
        AplotScenarioAxis::DeadlineAt => "DEADLINE_AT",
        AplotScenarioAxis::DeadlineAfter => "DEADLINE_AFTER",
        AplotScenarioAxis::UnknownService => "UNKNOWN_SERVICE",
    }
}

const fn host_name(axis: AplotHostAxis) -> &'static str {
    match axis {
        AplotHostAxis::Continue => "CONTINUE",
        AplotHostAxis::Terminate => "TERMINATE",
        AplotHostAxis::Timeout => "TIMEOUT",
        AplotHostAxis::Reconnect => "RECONNECT",
        AplotHostAxis::Loss => "LOSS",
    }
}

const fn resource_name(axis: AplotResourceAxis) -> &'static str {
    match axis {
        AplotResourceAxis::Nominal => "NOMINAL",
        AplotResourceAxis::FuelBoundary => "FUEL_BOUNDARY",
        AplotResourceAxis::MemoryBoundary => "MEMORY_BOUNDARY",
        AplotResourceAxis::HostCallBoundary => "HOST_CALL_BOUNDARY",
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
pub enum AplotMatrixExecutionError {
    #[error("APLOT matrix validation failed: {0}")]
    Matrix(String),
    #[error("APLOT matrix public sequence failed: {0}")]
    Sequence(String),
    #[error("APLOT differential execution failed: {0}")]
    Differential(String),
    #[error("APLOT matrix execution artifact serialization failed: {0}")]
    Serialization(String),
    #[error("APLOT matrix execution arithmetic overflow")]
    Arithmetic,
    #[error("APLOT matrix execution artifact violated its contract")]
    ArtifactContract,
}
