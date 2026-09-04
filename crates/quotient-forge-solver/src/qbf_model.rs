use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use quotient_forge_check::{check, CheckLimits, CheckOutcome};
use quotient_forge_synth::{MachineCell, ReleaseMachine, SynthesisProblem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::qbf::{CandidateRecord, QbfCompilation, QuantifierLayout, QBF_SEMANTICS_SCHEMA_V1};
use crate::qbf_solver::{
    QbfCandidateStatus, QbfSolverRun, QbfSolverStatus, QBF_SOLVER_RESULT_SCHEMA_V1,
};
use crate::qdimacs::{VariableRole, QDIMACS_SCHEMA_V1};

pub const QBF_CANDIDATE_DECISION_SCHEMA_V1: &str =
    "noticer.quotient_forge.qbf_candidate_decision.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QbfCandidateDecision {
    Accepted,
    Rejected,
    Inconclusive,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QbfIndependentCheckerStatus {
    Verified,
    Counterexample,
    Inconclusive,
    NotRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QbfCandidateDiagnostic {
    SolverNotSat,
    ArtifactContractMismatch,
    AssignmentMissing,
    AssignmentMalformed,
    AssignmentOutOfRange,
    DuplicateAssignment,
    ConflictingAssignment,
    MissingMachineAssignment,
    NoSelectedMachine,
    MultipleSelectedMachines,
    CandidateRegistryMismatch,
    CandidateRecordMalformed,
    CandidateHashMismatch,
    CheckerModelRejected,
    CheckerCounterexample,
    CheckerInconclusive,
    CheckerError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfCheckerLimitsRecord {
    pub max_nodes: u64,
    pub max_depth: u32,
    pub time_limit_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfIndependentCheckerEvidence {
    pub status: QbfIndependentCheckerStatus,
    pub limits: QbfCheckerLimitsRecord,
    pub explored_nodes: Option<u64>,
    pub reached_depth: Option<u32>,
    pub checked_horizon: Option<u32>,
    pub counterexample_slot: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfCandidateDecisionArtifact {
    pub schema_version: String,
    pub solver_result: QbfSolverStatus,
    pub decision: QbfCandidateDecision,
    pub candidate_accepted: bool,
    pub bounded_only: bool,
    pub candidate_id: Option<u32>,
    pub candidate_sha256: Option<String>,
    pub qdimacs_sha256: String,
    pub semantics_sha256: String,
    pub stdout_sha256: String,
    pub assignment_sha256: Option<String>,
    pub checker: QbfIndependentCheckerEvidence,
    pub diagnostic: Option<QbfCandidateDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedQbfCandidate {
    pub artifact: QbfCandidateDecisionArtifact,
    accepted_machine: Option<ReleaseMachine>,
}

#[derive(Debug, Error)]
pub enum QbfCandidateArtifactError {
    #[error("QBF candidate decision artifact is invalid: {0}")]
    Invalid(&'static str),
    #[error("QBF candidate decision JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("QBF candidate decision I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl CheckedQbfCandidate {
    #[must_use]
    pub fn accepted_machine(&self) -> Option<&ReleaseMachine> {
        self.accepted_machine.as_ref()
    }

    #[must_use]
    pub fn into_accepted_machine(self) -> Option<ReleaseMachine> {
        self.accepted_machine
    }
}

impl QbfCandidateDecisionArtifact {
    pub fn validate(&self) -> Result<(), QbfCandidateArtifactError> {
        if self.schema_version != QBF_CANDIDATE_DECISION_SCHEMA_V1 || !self.bounded_only {
            return Err(QbfCandidateArtifactError::Invalid("schema or bounded flag"));
        }
        for digest in [
            &self.qdimacs_sha256,
            &self.semantics_sha256,
            &self.stdout_sha256,
        ] {
            if !is_sha256(digest) {
                return Err(QbfCandidateArtifactError::Invalid("required digest"));
            }
        }
        if self
            .candidate_sha256
            .iter()
            .chain(self.assignment_sha256.iter())
            .any(|digest| !is_sha256(digest))
        {
            return Err(QbfCandidateArtifactError::Invalid("optional digest"));
        }

        let accepted = self.decision == QbfCandidateDecision::Accepted;
        if self.candidate_accepted != accepted {
            return Err(QbfCandidateArtifactError::Invalid(
                "decision/acceptance mismatch",
            ));
        }
        if accepted {
            if self.solver_result != QbfSolverStatus::Sat
                || self.checker.status != QbfIndependentCheckerStatus::Verified
                || self.candidate_id.is_none()
                || self.candidate_sha256.is_none()
                || self.assignment_sha256.is_none()
                || self.diagnostic.is_some()
            {
                return Err(QbfCandidateArtifactError::Invalid(
                    "accepted candidate lacks independent evidence",
                ));
            }
        } else if self.diagnostic.is_none() {
            return Err(QbfCandidateArtifactError::Invalid(
                "non-accepted decision lacks diagnostic",
            ));
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, QbfCandidateArtifactError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn write_canonical(&self, path: &Path) -> Result<(), QbfCandidateArtifactError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.canonical_json_bytes()?)?;
        Ok(())
    }
}

/// Decode a SAT assignment and accept a machine only after the independent AQRS checker.
///
/// The returned machine is private unless and until the checker reports `Verified`.
#[must_use]
pub fn check_qbf_candidate(
    run: &QbfSolverRun,
    compilation: &QbfCompilation,
    problem: &SynthesisProblem,
    limits: CheckLimits,
) -> CheckedQbfCandidate {
    let mut artifact = base_artifact(run, compilation, limits);
    if !artifacts_match(run, compilation) {
        return rejected(
            artifact,
            QbfCandidateDecision::Rejected,
            QbfCandidateDiagnostic::ArtifactContractMismatch,
        );
    }
    if run.artifact.result != QbfSolverStatus::Sat {
        return rejected(
            artifact,
            QbfCandidateDecision::NotApplicable,
            QbfCandidateDiagnostic::SolverNotSat,
        );
    }

    let assignment =
        match parse_assignment(&run.stdout, compilation.qdimacs.metadata.variable_count) {
            Ok(assignment) => assignment,
            Err(error) => {
                return rejected(
                    artifact,
                    QbfCandidateDecision::Rejected,
                    assignment_diagnostic(error),
                )
            }
        };
    artifact.assignment_sha256 = Some(hash_assignment(&assignment));

    let (candidate_id, machine) = match decode_machine(&assignment, compilation, problem) {
        Ok(decoded) => decoded,
        Err(error) => {
            return rejected(
                artifact,
                QbfCandidateDecision::Rejected,
                decode_diagnostic(error),
            )
        }
    };
    let machine_sha256 = sha256(&machine.canonical_bytes());
    artifact.candidate_id = Some(candidate_id);
    artifact.candidate_sha256 = Some(machine_sha256);

    let model = match problem.lower_candidate(&machine) {
        Ok(model) => model,
        Err(_) => {
            return rejected(
                artifact,
                QbfCandidateDecision::Rejected,
                QbfCandidateDiagnostic::CheckerModelRejected,
            )
        }
    };
    match check(&model, limits) {
        Ok(CheckOutcome::Verified(report)) => {
            artifact.decision = QbfCandidateDecision::Accepted;
            artifact.candidate_accepted = true;
            artifact.checker.status = QbfIndependentCheckerStatus::Verified;
            artifact.checker.explored_nodes = Some(saturating_u64(report.explored_nodes));
            artifact.checker.reached_depth = Some(report.reached_depth);
            artifact.checker.checked_horizon = Some(report.checked_horizon);
            artifact.diagnostic = None;
            CheckedQbfCandidate {
                artifact,
                accepted_machine: Some(machine),
            }
        }
        Ok(CheckOutcome::Counterexample(counterexample)) => {
            artifact.checker.status = QbfIndependentCheckerStatus::Counterexample;
            artifact.checker.counterexample_slot = Some(counterexample.slot);
            rejected(
                artifact,
                QbfCandidateDecision::Rejected,
                QbfCandidateDiagnostic::CheckerCounterexample,
            )
        }
        Ok(CheckOutcome::Inconclusive(report)) => {
            artifact.checker.status = QbfIndependentCheckerStatus::Inconclusive;
            artifact.checker.explored_nodes = Some(saturating_u64(report.explored_nodes));
            artifact.checker.reached_depth = Some(report.reached_depth);
            rejected(
                artifact,
                QbfCandidateDecision::Inconclusive,
                QbfCandidateDiagnostic::CheckerInconclusive,
            )
        }
        Err(_) => rejected(
            artifact,
            QbfCandidateDecision::Rejected,
            QbfCandidateDiagnostic::CheckerError,
        ),
    }
}

fn base_artifact(
    run: &QbfSolverRun,
    compilation: &QbfCompilation,
    limits: CheckLimits,
) -> QbfCandidateDecisionArtifact {
    let semantics = serde_json::to_vec(&compilation.metadata).unwrap_or_default();
    QbfCandidateDecisionArtifact {
        schema_version: QBF_CANDIDATE_DECISION_SCHEMA_V1.to_owned(),
        solver_result: run.artifact.result,
        decision: QbfCandidateDecision::Rejected,
        candidate_accepted: false,
        bounded_only: true,
        candidate_id: None,
        candidate_sha256: None,
        qdimacs_sha256: sha256(compilation.qdimacs.document.as_bytes()),
        semantics_sha256: sha256(&semantics),
        stdout_sha256: sha256(run.stdout.as_bytes()),
        assignment_sha256: None,
        checker: QbfIndependentCheckerEvidence {
            status: QbfIndependentCheckerStatus::NotRun,
            limits: QbfCheckerLimitsRecord {
                max_nodes: saturating_u64(limits.max_nodes),
                max_depth: limits.max_depth,
                time_limit_ms: u64::try_from(limits.time_limit.as_millis()).unwrap_or(u64::MAX),
            },
            explored_nodes: None,
            reached_depth: None,
            checked_horizon: None,
            counterexample_slot: None,
        },
        diagnostic: Some(QbfCandidateDiagnostic::ArtifactContractMismatch),
    }
}

fn artifacts_match(run: &QbfSolverRun, compilation: &QbfCompilation) -> bool {
    let qdimacs_sha256 = sha256(compilation.qdimacs.document.as_bytes());
    let expected_candidate_status = if run.artifact.result == QbfSolverStatus::Sat {
        QbfCandidateStatus::PendingIndependentCheck
    } else {
        QbfCandidateStatus::NotApplicable
    };
    run.artifact.schema_version == QBF_SOLVER_RESULT_SCHEMA_V1
        && compilation.qdimacs.metadata.schema_version == QDIMACS_SCHEMA_V1
        && compilation.metadata.schema_version == QBF_SEMANTICS_SCHEMA_V1
        && compilation.metadata.quantifier_layout == QuantifierLayout::MachineBeforeTrace
        && !compilation.metadata.non_production_mutant
        && compilation.qdimacs.metadata.qdimacs_sha256 == qdimacs_sha256
        && compilation.metadata.qdimacs_sha256 == qdimacs_sha256
        && run.artifact.qdimacs_sha256 == qdimacs_sha256
        && run.artifact.stdout_sha256 == sha256(run.stdout.as_bytes())
        && run.artifact.stderr_sha256 == sha256(run.stderr.as_bytes())
        && run.artifact.metadata.bounds == compilation.qdimacs.metadata.bounds
        && run.artifact.metadata.seed == compilation.qdimacs.metadata.seed
        && run.artifact.candidate_status == expected_candidate_status
        && !run.artifact.candidate_accepted
        && run.artifact.bounded_only
        && compilation.qdimacs.metadata.variable_count as usize
            == compilation.qdimacs.metadata.variables.len()
        && compilation.metadata.bounds.candidates as usize == compilation.metadata.candidates.len()
}

fn rejected(
    mut artifact: QbfCandidateDecisionArtifact,
    decision: QbfCandidateDecision,
    diagnostic: QbfCandidateDiagnostic,
) -> CheckedQbfCandidate {
    artifact.decision = decision;
    artifact.candidate_accepted = false;
    artifact.diagnostic = Some(diagnostic);
    CheckedQbfCandidate {
        artifact,
        accepted_machine: None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AssignmentError {
    Missing,
    Malformed,
    OutOfRange,
    Duplicate,
    Conflicting,
}

fn parse_assignment(
    stdout: &str,
    variable_count: u32,
) -> Result<BTreeMap<u32, bool>, AssignmentError> {
    let mut assignment = BTreeMap::new();
    let mut saw_assignment_line = false;
    for line in stdout.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens
            .first()
            .is_none_or(|token| !token.eq_ignore_ascii_case("v"))
        {
            continue;
        }
        saw_assignment_line = true;
        if tokens.len() < 3 || tokens.last() != Some(&"0") {
            return Err(AssignmentError::Malformed);
        }
        for token in &tokens[1..tokens.len() - 1] {
            let literal = token
                .parse::<i64>()
                .map_err(|_| AssignmentError::Malformed)?;
            let variable = literal
                .checked_abs()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(AssignmentError::OutOfRange)?;
            if variable == 0 || variable > variable_count {
                return Err(AssignmentError::OutOfRange);
            }
            let value = literal > 0;
            if let Some(previous) = assignment.insert(variable, value) {
                return Err(if previous == value {
                    AssignmentError::Duplicate
                } else {
                    AssignmentError::Conflicting
                });
            }
        }
    }
    if !saw_assignment_line || assignment.is_empty() {
        return Err(AssignmentError::Missing);
    }
    Ok(assignment)
}

fn assignment_diagnostic(error: AssignmentError) -> QbfCandidateDiagnostic {
    match error {
        AssignmentError::Missing => QbfCandidateDiagnostic::AssignmentMissing,
        AssignmentError::Malformed => QbfCandidateDiagnostic::AssignmentMalformed,
        AssignmentError::OutOfRange => QbfCandidateDiagnostic::AssignmentOutOfRange,
        AssignmentError::Duplicate => QbfCandidateDiagnostic::DuplicateAssignment,
        AssignmentError::Conflicting => QbfCandidateDiagnostic::ConflictingAssignment,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeError {
    MissingMachineAssignment,
    NoSelectedMachine,
    MultipleSelectedMachines,
    RegistryMismatch,
    RecordMalformed,
    HashMismatch,
}

fn decode_machine(
    assignment: &BTreeMap<u32, bool>,
    compilation: &QbfCompilation,
    problem: &SynthesisProblem,
) -> Result<(u32, ReleaseMachine), DecodeError> {
    let machine_variables = compilation
        .qdimacs
        .metadata
        .variables
        .iter()
        .filter(|record| record.role == VariableRole::MachineChoice)
        .collect::<Vec<_>>();
    if machine_variables.is_empty() {
        return Err(DecodeError::RegistryMismatch);
    }

    let mut registry_ids = BTreeSet::new();
    let mut selected = Vec::new();
    for variable in machine_variables {
        let [candidate_id] = variable.coordinates.as_slice() else {
            return Err(DecodeError::RegistryMismatch);
        };
        if !registry_ids.insert(*candidate_id) {
            return Err(DecodeError::RegistryMismatch);
        }
        let value = assignment
            .get(&variable.id)
            .copied()
            .ok_or(DecodeError::MissingMachineAssignment)?;
        if value {
            selected.push(*candidate_id);
        }
    }

    let mut candidate_ids = BTreeSet::new();
    if compilation
        .metadata
        .candidates
        .iter()
        .any(|candidate| !candidate_ids.insert(candidate.id))
        || candidate_ids != registry_ids
    {
        return Err(DecodeError::RegistryMismatch);
    }
    let candidate_id = match selected.as_slice() {
        [] => return Err(DecodeError::NoSelectedMachine),
        [candidate_id] => *candidate_id,
        _ => return Err(DecodeError::MultipleSelectedMachines),
    };
    let record = compilation
        .metadata
        .candidates
        .iter()
        .find(|candidate| candidate.id == candidate_id)
        .ok_or(DecodeError::RegistryMismatch)?;
    let machine = machine_from_record(record, problem)?;
    if sha256(&machine.canonical_bytes()) != record.canonical_sha256 {
        return Err(DecodeError::HashMismatch);
    }
    Ok((candidate_id, machine))
}

fn machine_from_record(
    record: &CandidateRecord,
    problem: &SynthesisProblem,
) -> Result<ReleaseMachine, DecodeError> {
    if record.state_count == 0
        || record.symbol_count == 0
        || record.symbol_count != problem.machine_symbol_count
    {
        return Err(DecodeError::RecordMalformed);
    }
    let expected = usize::try_from(record.state_count)
        .ok()
        .and_then(|states| {
            usize::try_from(record.symbol_count)
                .ok()
                .and_then(|symbols| states.checked_mul(symbols))
        })
        .ok_or(DecodeError::RecordMalformed)?;
    if record.cells.len() != expected {
        return Err(DecodeError::RecordMalformed);
    }

    let mut by_coordinate = BTreeMap::new();
    for cell in &record.cells {
        if cell.machine_state >= record.state_count
            || cell.symbol >= record.symbol_count
            || by_coordinate
                .insert(
                    (cell.machine_state, cell.symbol),
                    MachineCell {
                        next_state: cell.next_state,
                        output: cell.output,
                    },
                )
                .is_some()
        {
            return Err(DecodeError::RecordMalformed);
        }
    }
    let mut cells = Vec::with_capacity(expected);
    for state in 0..record.state_count {
        for symbol in 0..record.symbol_count {
            cells.push(
                by_coordinate
                    .get(&(state, symbol))
                    .copied()
                    .ok_or(DecodeError::RecordMalformed)?,
            );
        }
    }
    let machine = ReleaseMachine {
        state_count: record.state_count,
        symbol_count: record.symbol_count,
        cells,
    };
    machine
        .validate(problem.machine_symbol_count, problem.outputs.len())
        .map_err(|_| DecodeError::RecordMalformed)?;
    Ok(machine)
}

fn decode_diagnostic(error: DecodeError) -> QbfCandidateDiagnostic {
    match error {
        DecodeError::MissingMachineAssignment => QbfCandidateDiagnostic::MissingMachineAssignment,
        DecodeError::NoSelectedMachine => QbfCandidateDiagnostic::NoSelectedMachine,
        DecodeError::MultipleSelectedMachines => QbfCandidateDiagnostic::MultipleSelectedMachines,
        DecodeError::RegistryMismatch => QbfCandidateDiagnostic::CandidateRegistryMismatch,
        DecodeError::RecordMalformed => QbfCandidateDiagnostic::CandidateRecordMalformed,
        DecodeError::HashMismatch => QbfCandidateDiagnostic::CandidateHashMismatch,
    }
}

fn hash_assignment(assignment: &BTreeMap<u32, bool>) -> String {
    let mut canonical = String::new();
    for (variable, value) in assignment {
        writeln!(canonical, "{variable}={}", u8::from(*value)).unwrap();
    }
    sha256(canonical.as_bytes())
}

fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
