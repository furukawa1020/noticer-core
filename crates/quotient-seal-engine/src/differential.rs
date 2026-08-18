use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ContractError, EngineRunArtifact, EngineRunVerdict, ExecutionInput, ExecutionLimits,
    ExecutionTermination, ObservableAxis, ObservableEvent,
};

pub const DIFFERENTIAL_ORACLE_VERSION: &str = "quotient-seal-differential-oracle/v1";
pub const DIFFERENTIAL_ORACLE_ARTIFACT_SCHEMA_VERSION: &str =
    "quotient-seal-differential-result/v1";
pub const REFERENCE_ENGINE_NAME: &str = "quotient-seal-small-step";
const REQUIRED_ENGINES: [&str; 2] = ["wasmi", "wasmtime"];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DifferentialVerdict {
    Match,
    Counterexample,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DifferentialCounterexampleKind {
    EngineDisagreement,
    ReferenceDisagreement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComparisonPoint {
    Trace {
        index: u64,
        left_axis: Option<ObservableAxis>,
        right_axis: Option<ObservableAxis>,
        left: Option<ObservableEvent>,
        right: Option<ObservableEvent>,
    },
    Termination {
        left_axis: ObservableAxis,
        right_axis: ObservableAxis,
        left: ExecutionTermination,
        right: ExecutionTermination,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialCounterexample {
    pub kind: DifferentialCounterexampleKind,
    pub left_participant: String,
    pub right_participant: String,
    pub first_difference: ComparisonPoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnresolvedEvidence {
    InvalidReferenceIdentity {
        actual: String,
    },
    MissingRequiredEngine {
        engine: String,
    },
    DuplicateEngine {
        engine: String,
    },
    InputMismatch {
        participant: String,
        expected_sha256: String,
        actual_sha256: String,
    },
    ParserDisagreement {
        rejected_participants: Vec<String>,
    },
    ParserRejected {
        participants: Vec<String>,
    },
    Unsupported {
        participant: String,
    },
    ResourceBound {
        participant: String,
    },
    EngineFailure {
        participant: String,
    },
    NonExecuted {
        participant: String,
        verdict: EngineRunVerdict,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialOracleArtifact {
    pub schema_version: String,
    pub oracle_version: String,
    pub shared_input_sha256: String,
    pub verdict: DifferentialVerdict,
    pub counterexamples: Vec<DifferentialCounterexample>,
    pub unresolved: Vec<UnresolvedEvidence>,
    pub reference: EngineRunArtifact,
    pub engines: Vec<EngineRunArtifact>,
}

impl DifferentialOracleArtifact {
    pub fn validate(&self) -> Result<(), DifferentialOracleError> {
        if self.schema_version != DIFFERENTIAL_ORACLE_ARTIFACT_SCHEMA_VERSION {
            return Err(DifferentialOracleError::SchemaVersion {
                expected: DIFFERENTIAL_ORACLE_ARTIFACT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.oracle_version != DIFFERENTIAL_ORACLE_VERSION {
            return Err(DifferentialOracleError::OracleVersion);
        }
        let mut engines = self.engines.clone();
        sort_engines(&mut engines);
        if engines != self.engines {
            return Err(DifferentialOracleError::NonCanonicalEngineOrder);
        }
        let expected = evaluate_parts(&self.reference, &self.engines)?;
        if self.shared_input_sha256 != expected.shared_input_sha256
            || self.verdict != expected.verdict
            || self.counterexamples != expected.counterexamples
            || self.unresolved != expected.unresolved
        {
            return Err(DifferentialOracleError::RecomputedResultMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, DifferentialOracleError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn artifact_sha256(&self) -> Result<String, DifferentialOracleError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }

    pub fn write_json(&self, path: &Path) -> Result<(), DifferentialOracleError> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DifferentialOracle;

impl DifferentialOracle {
    pub fn evaluate(
        reference: EngineRunArtifact,
        mut engines: Vec<EngineRunArtifact>,
    ) -> Result<DifferentialOracleArtifact, DifferentialOracleError> {
        sort_engines(&mut engines);
        let evaluation = evaluate_parts(&reference, &engines)?;
        let artifact = DifferentialOracleArtifact {
            schema_version: DIFFERENTIAL_ORACLE_ARTIFACT_SCHEMA_VERSION.to_owned(),
            oracle_version: DIFFERENTIAL_ORACLE_VERSION.to_owned(),
            shared_input_sha256: evaluation.shared_input_sha256,
            verdict: evaluation.verdict,
            counterexamples: evaluation.counterexamples,
            unresolved: evaluation.unresolved,
            reference,
            engines,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

struct Evaluation {
    shared_input_sha256: String,
    verdict: DifferentialVerdict,
    counterexamples: Vec<DifferentialCounterexample>,
    unresolved: Vec<UnresolvedEvidence>,
}

fn evaluate_parts(
    reference: &EngineRunArtifact,
    engines: &[EngineRunArtifact],
) -> Result<Evaluation, DifferentialOracleError> {
    reference.validate()?;
    for engine in engines {
        engine.validate()?;
    }

    let shared_input_sha256 = shared_input_sha256(&reference.input)?;
    let mut unresolved = structural_unresolved(reference, engines, &shared_input_sha256)?;
    unresolved.extend(execution_unresolved(reference, engines));
    if !unresolved.is_empty() {
        return Ok(Evaluation {
            shared_input_sha256,
            verdict: DifferentialVerdict::Unresolved,
            counterexamples: Vec::new(),
            unresolved,
        });
    }

    let mut counterexamples = Vec::new();
    for left_index in 0..engines.len() {
        for right in &engines[left_index + 1..] {
            let left = &engines[left_index];
            if let Some(first_difference) = first_difference(left, right) {
                counterexamples.push(DifferentialCounterexample {
                    kind: DifferentialCounterexampleKind::EngineDisagreement,
                    left_participant: participant(left),
                    right_participant: participant(right),
                    first_difference,
                });
            }
        }
    }
    for engine in engines {
        if let Some(first_difference) = first_difference(reference, engine) {
            counterexamples.push(DifferentialCounterexample {
                kind: DifferentialCounterexampleKind::ReferenceDisagreement,
                left_participant: participant(reference),
                right_participant: participant(engine),
                first_difference,
            });
        }
    }

    Ok(Evaluation {
        shared_input_sha256,
        verdict: if counterexamples.is_empty() {
            DifferentialVerdict::Match
        } else {
            DifferentialVerdict::Counterexample
        },
        counterexamples,
        unresolved: Vec::new(),
    })
}

fn structural_unresolved(
    reference: &EngineRunArtifact,
    engines: &[EngineRunArtifact],
    expected_input: &str,
) -> Result<Vec<UnresolvedEvidence>, DifferentialOracleError> {
    let mut unresolved = Vec::new();
    if reference.input.engine.name != REFERENCE_ENGINE_NAME {
        unresolved.push(UnresolvedEvidence::InvalidReferenceIdentity {
            actual: reference.input.engine.name.clone(),
        });
    }
    for required in REQUIRED_ENGINES {
        if !engines
            .iter()
            .any(|engine| engine.input.engine.name == required)
        {
            unresolved.push(UnresolvedEvidence::MissingRequiredEngine {
                engine: required.to_owned(),
            });
        }
    }
    for pair in engines.windows(2) {
        if pair[0].input.engine.name == pair[1].input.engine.name {
            unresolved.push(UnresolvedEvidence::DuplicateEngine {
                engine: pair[0].input.engine.name.clone(),
            });
        }
    }
    for run in engines {
        let actual = shared_input_sha256(&run.input)?;
        if actual != expected_input {
            unresolved.push(UnresolvedEvidence::InputMismatch {
                participant: participant(run),
                expected_sha256: expected_input.to_owned(),
                actual_sha256: actual,
            });
        }
    }
    Ok(unresolved)
}

fn execution_unresolved(
    reference: &EngineRunArtifact,
    engines: &[EngineRunArtifact],
) -> Vec<UnresolvedEvidence> {
    let runs: Vec<&EngineRunArtifact> = std::iter::once(reference).chain(engines).collect();
    let rejected: Vec<String> = runs
        .iter()
        .filter(|run| matches!(run.termination, ExecutionTermination::InvalidModule { .. }))
        .map(|run| participant(run))
        .collect();
    let mut unresolved = Vec::new();
    if !rejected.is_empty() {
        if rejected.len() == runs.len() {
            unresolved.push(UnresolvedEvidence::ParserRejected {
                participants: rejected,
            });
        } else {
            unresolved.push(UnresolvedEvidence::ParserDisagreement {
                rejected_participants: rejected,
            });
        }
    }
    for run in runs {
        if run.verdict == EngineRunVerdict::Executed {
            continue;
        }
        let evidence = match run.termination {
            ExecutionTermination::InvalidModule { .. } => continue,
            ExecutionTermination::Unsupported { .. } => UnresolvedEvidence::Unsupported {
                participant: participant(run),
            },
            ExecutionTermination::ResourceExhausted { .. }
            | ExecutionTermination::TimedOut { .. } => UnresolvedEvidence::ResourceBound {
                participant: participant(run),
            },
            ExecutionTermination::EngineFailure { .. } => UnresolvedEvidence::EngineFailure {
                participant: participant(run),
            },
            _ => UnresolvedEvidence::NonExecuted {
                participant: participant(run),
                verdict: run.verdict,
            },
        };
        unresolved.push(evidence);
    }
    unresolved
}

fn first_difference(
    left: &EngineRunArtifact,
    right: &EngineRunArtifact,
) -> Option<ComparisonPoint> {
    let trace_length = left.trace.len().max(right.trace.len());
    for index in 0..trace_length {
        let left_event = left.trace.get(index);
        let right_event = right.trace.get(index);
        if left_event != right_event {
            return Some(ComparisonPoint::Trace {
                index: u64::try_from(index).unwrap_or(u64::MAX),
                left_axis: left_event.map(event_axis),
                right_axis: right_event.map(event_axis),
                left: left_event.cloned(),
                right: right_event.cloned(),
            });
        }
    }
    if left.termination != right.termination {
        return Some(ComparisonPoint::Termination {
            left_axis: termination_axis(&left.termination),
            right_axis: termination_axis(&right.termination),
            left: left.termination.clone(),
            right: right.termination.clone(),
        });
    }
    None
}

fn event_axis(event: &ObservableEvent) -> ObservableAxis {
    match event {
        ObservableEvent::ApiCall { .. } | ObservableEvent::ApiReturn { .. } => {
            ObservableAxis::Return
        }
        ObservableEvent::EmitFrame { .. }
        | ObservableEvent::EmitAction { .. }
        | ObservableEvent::PublicFailure { .. } => ObservableAxis::Output,
        ObservableEvent::HostImport { .. } => ObservableAxis::HostImport,
        ObservableEvent::Reset { .. } => ObservableAxis::Reset,
        ObservableEvent::Handoff { .. } => ObservableAxis::Handoff,
        ObservableEvent::PublicState { .. } => ObservableAxis::PublicState,
    }
}

fn termination_axis(termination: &ExecutionTermination) -> ObservableAxis {
    match termination {
        ExecutionTermination::Trapped { .. } => ObservableAxis::Trap,
        _ => ObservableAxis::Return,
    }
}

fn sort_engines(engines: &mut [EngineRunArtifact]) {
    engines.sort_by(|left, right| {
        (
            &left.input.engine.name,
            &left.input.engine.version,
            &left.input.engine.executable_sha256,
        )
            .cmp(&(
                &right.input.engine.name,
                &right.input.engine.version,
                &right.input.engine.executable_sha256,
            ))
    });
}

fn participant(run: &EngineRunArtifact) -> String {
    format!("{}@{}", run.input.engine.name, run.input.engine.version)
}

#[derive(Serialize)]
struct SharedInput<'a> {
    module_sha256: &'a str,
    abi_sha256: &'a str,
    host_tape: &'a crate::HostTapeRecord,
    context_sequence: &'a [crate::ContextCommandRecord],
    limits: &'a ExecutionLimits,
}

fn shared_input_sha256(input: &ExecutionInput) -> Result<String, DifferentialOracleError> {
    let shared = SharedInput {
        module_sha256: &input.module_sha256,
        abi_sha256: &input.abi_sha256,
        host_tape: &input.host_tape,
        context_sequence: &input.context_sequence,
        limits: &input.limits,
    };
    Ok(sha256_hex(&serde_json::to_vec(&shared)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error)]
pub enum DifferentialOracleError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("oracle version is not supported")]
    OracleVersion,
    #[error("engine artifacts are not in canonical identity order")]
    NonCanonicalEngineOrder,
    #[error("stored oracle result does not match independent recomputation")]
    RecomputedResultMismatch,
}
