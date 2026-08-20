use quotient_seal_engine::HostOutcomeRecord;
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostFault, PublicHostTape};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    evaluate_atv2_differential_with_host_tape, Atv2AdversarialMatrix, Atv2CompiledQsm,
    Atv2DifferentialArtifact, Atv2DifferentialVerdict, Atv2EngineDigests, Atv2HostAxis,
    Atv2MatrixLimits, Atv2PublicSequence, Atv2ResourceAxis, Atv2ScenarioAxis,
};

pub const ATV2_MATRIX_EXECUTION_VERSION: &str = "noticer-atv2-matrix-execution/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Atv2HostInjection {
    NotRequested,
    Applied {
        directive_index: u32,
        outcome: HostOutcomeRecord,
    },
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atv2MatrixCaseArtifact {
    pub case_id_sha256: String,
    pub scenario_axis: String,
    pub host_axis: String,
    pub resource_axis: String,
    pub injection: Atv2HostInjection,
    pub verdict: Atv2DifferentialVerdict,
    pub differential: Atv2DifferentialArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atv2MatrixExecutionArtifact {
    pub schema_version: String,
    pub evaluator_version: String,
    pub matrix_digest_sha256: String,
    pub matrix_bytes_sha256: String,
    pub hardware_status: String,
    pub verdict: Atv2DifferentialVerdict,
    pub match_cases: u32,
    pub counterexample_cases: u32,
    pub unresolved_cases: u32,
    pub cases: Vec<Atv2MatrixCaseArtifact>,
}

impl Atv2MatrixExecutionArtifact {
    pub fn validate(&self) -> Result<(), Atv2MatrixExecutionError> {
        if self.schema_version != ATV2_MATRIX_EXECUTION_VERSION
            || self.evaluator_version != ATV2_MATRIX_EXECUTION_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.matrix_digest_sha256)
            || !is_sha256(&self.matrix_bytes_sha256)
            || self.cases.is_empty()
        {
            return Err(Atv2MatrixExecutionError::ArtifactContract);
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
                return Err(Atv2MatrixExecutionError::ArtifactContract);
            }
            previous = Some(case.case_id_sha256.as_str());
            case.differential
                .validate()
                .map_err(|error| Atv2MatrixExecutionError::Differential(error.to_string()))?;
            let expected = if case.injection == Atv2HostInjection::NotApplicable {
                Atv2DifferentialVerdict::Unresolved
            } else {
                case.differential.verdict
            };
            if expected != case.verdict {
                return Err(Atv2MatrixExecutionError::ArtifactContract);
            }
            match case.verdict {
                Atv2DifferentialVerdict::Match => matched = checked_increment(matched)?,
                Atv2DifferentialVerdict::Counterexample => {
                    counterexamples = checked_increment(counterexamples)?;
                }
                Atv2DifferentialVerdict::Unresolved => {
                    unresolved = checked_increment(unresolved)?;
                }
            }
        }
        if self.match_cases != matched
            || self.counterexample_cases != counterexamples
            || self.unresolved_cases != unresolved
            || self.verdict != aggregate_verdict(&self.cases)
        {
            return Err(Atv2MatrixExecutionError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, Atv2MatrixExecutionError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| Atv2MatrixExecutionError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, Atv2MatrixExecutionError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn evaluate_atv2_adversarial_matrix(
    compiled: &Atv2CompiledQsm,
    matrix: &Atv2AdversarialMatrix,
    matrix_limits: Atv2MatrixLimits,
    engine_digests: &Atv2EngineDigests,
) -> Result<Atv2MatrixExecutionArtifact, Atv2MatrixExecutionError> {
    matrix
        .validate_against(compiled, matrix_limits)
        .map_err(|error| Atv2MatrixExecutionError::Matrix(error.to_string()))?;
    let matrix_bytes = matrix
        .canonical_bytes()
        .map_err(|error| Atv2MatrixExecutionError::Matrix(error.to_string()))?;
    let mut cases = Vec::with_capacity(matrix.cases().len());
    for case in matrix.cases() {
        let sequence = Atv2PublicSequence::new(
            compiled,
            case.commands().to_vec(),
            case.limits(),
            matrix_limits.max_commands_per_case,
        )
        .map_err(|error| Atv2MatrixExecutionError::Sequence(error.to_string()))?;
        let (host_tape, injection) = inject_host_axis(case.host(), sequence.host_tape())?;
        let differential = evaluate_atv2_differential_with_host_tape(
            compiled,
            &sequence,
            &host_tape,
            engine_digests,
        )
        .map_err(|error| Atv2MatrixExecutionError::Differential(error.to_string()))?;
        let verdict = if injection == Atv2HostInjection::NotApplicable {
            Atv2DifferentialVerdict::Unresolved
        } else {
            differential.verdict
        };
        cases.push(Atv2MatrixCaseArtifact {
            case_id_sha256: case.case_id().to_hex(),
            scenario_axis: scenario_name(case.scenario()).to_owned(),
            host_axis: host_name(case.host()).to_owned(),
            resource_axis: resource_name(case.resource()).to_owned(),
            injection,
            verdict,
            differential,
        });
    }
    let match_cases = count_verdict(&cases, Atv2DifferentialVerdict::Match)?;
    let counterexample_cases = count_verdict(&cases, Atv2DifferentialVerdict::Counterexample)?;
    let unresolved_cases = count_verdict(&cases, Atv2DifferentialVerdict::Unresolved)?;
    let artifact = Atv2MatrixExecutionArtifact {
        schema_version: ATV2_MATRIX_EXECUTION_VERSION.to_owned(),
        evaluator_version: ATV2_MATRIX_EXECUTION_VERSION.to_owned(),
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
    axis: Atv2HostAxis,
    base: &PublicHostTape,
) -> Result<(PublicHostTape, Atv2HostInjection), Atv2MatrixExecutionError> {
    if axis == Atv2HostAxis::Continue {
        return Ok((base.clone(), Atv2HostInjection::NotRequested));
    }
    let Some(first) = base.directives().first() else {
        return Ok((base.clone(), Atv2HostInjection::NotApplicable));
    };
    let outcome = match axis {
        Atv2HostAxis::Continue => unreachable!("handled above"),
        Atv2HostAxis::Terminate => HostOutcome::Terminate,
        Atv2HostAxis::Timeout => HostOutcome::Fault(PublicHostFault::Timeout),
        Atv2HostAxis::Reconnect => HostOutcome::Fault(PublicHostFault::Reconnect),
        Atv2HostAxis::Loss => HostOutcome::Fault(PublicHostFault::Loss),
    };
    let import = first.import().to_owned();
    let mut directives = base.directives().to_vec();
    directives[0] = HostDirective::new(import, outcome);
    Ok((
        PublicHostTape::new(directives),
        Atv2HostInjection::Applied {
            directive_index: 0,
            outcome: HostOutcomeRecord::from(outcome),
        },
    ))
}

fn count_verdict(
    cases: &[Atv2MatrixCaseArtifact],
    verdict: Atv2DifferentialVerdict,
) -> Result<u32, Atv2MatrixExecutionError> {
    u32::try_from(cases.iter().filter(|case| case.verdict == verdict).count())
        .map_err(|_| Atv2MatrixExecutionError::Arithmetic)
}

fn checked_increment(value: u32) -> Result<u32, Atv2MatrixExecutionError> {
    value
        .checked_add(1)
        .ok_or(Atv2MatrixExecutionError::Arithmetic)
}

fn aggregate_verdict(cases: &[Atv2MatrixCaseArtifact]) -> Atv2DifferentialVerdict {
    if cases
        .iter()
        .any(|case| case.verdict == Atv2DifferentialVerdict::Unresolved)
    {
        Atv2DifferentialVerdict::Unresolved
    } else if cases
        .iter()
        .any(|case| case.verdict == Atv2DifferentialVerdict::Counterexample)
    {
        Atv2DifferentialVerdict::Counterexample
    } else {
        Atv2DifferentialVerdict::Match
    }
}

const fn scenario_name(axis: Atv2ScenarioAxis) -> &'static str {
    match axis {
        Atv2ScenarioAxis::Normal => "NORMAL",
        Atv2ScenarioAxis::PublicFaultTimeout => "PUBLIC_FAULT_TIMEOUT",
        Atv2ScenarioAxis::PublicFaultReconnect => "PUBLIC_FAULT_RECONNECT",
        Atv2ScenarioAxis::PublicFaultLoss => "PUBLIC_FAULT_LOSS",
        Atv2ScenarioAxis::Reset => "RESET",
        Atv2ScenarioAxis::Handoff => "HANDOFF",
        Atv2ScenarioAxis::DeadlineBefore => "DEADLINE_BEFORE",
        Atv2ScenarioAxis::DeadlineAt => "DEADLINE_AT",
        Atv2ScenarioAxis::DeadlineAfter => "DEADLINE_AFTER",
        Atv2ScenarioAxis::UnknownService => "UNKNOWN_SERVICE",
    }
}

const fn host_name(axis: Atv2HostAxis) -> &'static str {
    match axis {
        Atv2HostAxis::Continue => "CONTINUE",
        Atv2HostAxis::Terminate => "TERMINATE",
        Atv2HostAxis::Timeout => "TIMEOUT",
        Atv2HostAxis::Reconnect => "RECONNECT",
        Atv2HostAxis::Loss => "LOSS",
    }
}

const fn resource_name(axis: Atv2ResourceAxis) -> &'static str {
    match axis {
        Atv2ResourceAxis::Nominal => "NOMINAL",
        Atv2ResourceAxis::FuelBoundary => "FUEL_BOUNDARY",
        Atv2ResourceAxis::MemoryBoundary => "MEMORY_BOUNDARY",
        Atv2ResourceAxis::HostCallBoundary => "HOST_CALL_BOUNDARY",
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
pub enum Atv2MatrixExecutionError {
    #[error("ATV2 matrix validation failed: {0}")]
    Matrix(String),
    #[error("ATV2 matrix public sequence failed: {0}")]
    Sequence(String),
    #[error("ATV2 differential execution failed: {0}")]
    Differential(String),
    #[error("ATV2 matrix execution artifact serialization failed: {0}")]
    Serialization(String),
    #[error("ATV2 matrix execution arithmetic overflow")]
    Arithmetic,
    #[error("ATV2 matrix execution artifact violated its contract")]
    ArtifactContract,
}
