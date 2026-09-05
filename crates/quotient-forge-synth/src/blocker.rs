use std::collections::BTreeMap;

use quotient_forge_check::{
    check, CheckLimits, CheckOutcome, Counterexample, CounterexampleKind, ModelError, ObligationRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{MachineCell, ProblemError, ReleaseMachine, SynthesisProblem};
use crate::search::{blocking_clause_from_counterexample, BlockingClause, DecisionAssignment};

pub const TYPED_BLOCKER_SCHEMA_V1: &str = "noticer.quotient_forge.typed_blocker.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockerClass {
    Security,
    Utility,
    Fault,
}

impl BlockerClass {
    #[must_use]
    pub const fn for_counterexample(kind: &CounterexampleKind) -> Self {
        match kind {
            CounterexampleKind::SecurityDivergence => Self::Security,
            CounterexampleKind::UnauthorizedAction { .. }
            | CounterexampleKind::DuplicateAction { .. }
            | CounterexampleKind::MissedDeadline { .. } => Self::Utility,
            CounterexampleKind::RecoverableFaultViolation { .. } => Self::Fault,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockerAssignmentRecord {
    pub machine_state: u32,
    pub symbol: u32,
    pub next_state: u32,
    pub output: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBlockerArtifact {
    pub schema_version: String,
    pub bounded_only: bool,
    pub class: BlockerClass,
    pub epoch: u64,
    pub problem_sha256: String,
    pub source_candidate_sha256: String,
    pub counterexample_sha256: String,
    pub blocker_sha256: String,
    pub assignments: Vec<BlockerAssignmentRecord>,
}

impl TypedBlockerArtifact {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn validate(&self) -> Result<(), TypedBlockerError> {
        if self.schema_version != TYPED_BLOCKER_SCHEMA_V1 || !self.bounded_only {
            return Err(TypedBlockerError::InvalidArtifact(
                "schema or bounded-only flag",
            ));
        }
        if !is_sha256(&self.problem_sha256)
            || !is_sha256(&self.source_candidate_sha256)
            || !is_sha256(&self.counterexample_sha256)
            || !is_sha256(&self.blocker_sha256)
        {
            return Err(TypedBlockerError::InvalidArtifact("digest format"));
        }
        if self.assignments.is_empty()
            || self
                .assignments
                .windows(2)
                .any(|pair| assignment_key(pair[0]) >= assignment_key(pair[1]))
        {
            return Err(TypedBlockerError::InvalidArtifact(
                "assignments are empty or non-canonical",
            ));
        }
        if self.blocker_sha256 != blocker_digest(self)? {
            return Err(TypedBlockerError::InvalidArtifact(
                "blocker digest mismatch",
            ));
        }
        Ok(())
    }
}

const fn assignment_key(value: BlockerAssignmentRecord) -> (u32, u32) {
    (value.machine_state, value.symbol)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedBlocker {
    artifact: TypedBlockerArtifact,
    clause: BlockingClause,
}

impl TypedBlocker {
    pub fn from_counterexample(
        problem: &SynthesisProblem,
        source_candidate: &ReleaseMachine,
        counterexample: &Counterexample,
        epoch: u64,
    ) -> Result<Self, TypedBlockerError> {
        problem.validate()?;
        source_candidate.validate(problem.machine_symbol_count, problem.outputs.len())?;
        let signature =
            quotient_forge_check::CounterexampleSignature::from_counterexample(counterexample)?;
        let clause = blocking_clause_from_counterexample(problem, source_candidate, counterexample)
            .ok_or(TypedBlockerError::CounterexampleDidNotProduceBlocker)?;
        if !clause.blocks(source_candidate) {
            return Err(TypedBlockerError::SourceCandidateNotExcluded);
        }
        let assignments = clause
            .assignments
            .iter()
            .map(|assignment| BlockerAssignmentRecord {
                machine_state: assignment.machine_state,
                symbol: assignment.symbol,
                next_state: assignment.decision.next_state,
                output: assignment.decision.output,
            })
            .collect();
        let mut artifact = TypedBlockerArtifact {
            schema_version: TYPED_BLOCKER_SCHEMA_V1.to_owned(),
            bounded_only: true,
            class: BlockerClass::for_counterexample(&counterexample.kind),
            epoch,
            problem_sha256: synthesis_problem_sha256(problem)?,
            source_candidate_sha256: candidate_sha256(source_candidate),
            counterexample_sha256: signature.digest_sha256,
            blocker_sha256: String::new(),
            assignments,
        };
        artifact.blocker_sha256 = blocker_digest(&artifact)?;
        artifact.validate()?;
        Ok(Self { artifact, clause })
    }

    pub fn from_artifact(artifact: TypedBlockerArtifact) -> Result<Self, TypedBlockerError> {
        artifact.validate()?;
        let clause = BlockingClause {
            assignments: artifact
                .assignments
                .iter()
                .map(|assignment| DecisionAssignment {
                    machine_state: assignment.machine_state,
                    symbol: assignment.symbol,
                    decision: MachineCell {
                        next_state: assignment.next_state,
                        output: assignment.output,
                    },
                })
                .collect(),
        };
        Ok(Self { artifact, clause })
    }

    #[must_use]
    pub const fn artifact(&self) -> &TypedBlockerArtifact {
        &self.artifact
    }

    #[must_use]
    pub fn blocks(&self, candidate: &ReleaseMachine) -> bool {
        self.clause.blocks(candidate)
    }

    pub fn validate_context(
        &self,
        problem: &SynthesisProblem,
        epoch: u64,
    ) -> Result<(), TypedBlockerError> {
        self.artifact.validate()?;
        if self.artifact.epoch != epoch {
            return Err(TypedBlockerError::StaleEpoch {
                expected: epoch,
                artifact: self.artifact.epoch,
            });
        }
        let current_problem = synthesis_problem_sha256(problem)?;
        if self.artifact.problem_sha256 != current_problem {
            return Err(TypedBlockerError::StaleProblem);
        }
        Ok(())
    }

    pub fn verify_source_candidate(
        &self,
        problem: &SynthesisProblem,
        source_candidate: &ReleaseMachine,
        epoch: u64,
    ) -> Result<(), TypedBlockerError> {
        self.validate_context(problem, epoch)?;
        if self.artifact.source_candidate_sha256 != candidate_sha256(source_candidate) {
            return Err(TypedBlockerError::SourceCandidateMismatch);
        }
        if !self.blocks(source_candidate) {
            return Err(TypedBlockerError::SourceCandidateNotExcluded);
        }
        Ok(())
    }

    pub fn audit_candidate(
        &self,
        problem: &SynthesisProblem,
        candidate: &ReleaseMachine,
        epoch: u64,
        checker_limits: CheckLimits,
    ) -> Result<BlockerAudit, TypedBlockerError> {
        self.validate_context(problem, epoch)?;
        if !self.blocks(candidate) {
            return Ok(BlockerAudit::NotExcluded);
        }
        if self.artifact.source_candidate_sha256 == candidate_sha256(candidate) {
            return Ok(BlockerAudit::SourceCandidateExcluded);
        }
        let model = problem.lower_candidate(candidate)?;
        match check(&model, checker_limits)? {
            CheckOutcome::Verified(_) => Ok(BlockerAudit::OverExcludesVerifiedCandidate),
            CheckOutcome::Counterexample(_) => Ok(BlockerAudit::InvalidCandidateExcluded),
            CheckOutcome::Inconclusive(_) => Ok(BlockerAudit::CheckerInconclusive),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockerAudit {
    NotExcluded,
    SourceCandidateExcluded,
    InvalidCandidateExcluded,
    OverExcludesVerifiedCandidate,
    CheckerInconclusive,
}

#[derive(Debug, Error)]
pub enum TypedBlockerError {
    #[error("invalid synthesis problem or candidate: {0}")]
    Problem(#[from] ProblemError),
    #[error("counterexample signature or blocker JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("independent checker rejected the candidate: {0}")]
    Checker(#[from] ModelError),
    #[error("counterexample did not produce a blocker")]
    CounterexampleDidNotProduceBlocker,
    #[error("blocker does not exclude its source candidate")]
    SourceCandidateNotExcluded,
    #[error("source candidate digest does not match blocker provenance")]
    SourceCandidateMismatch,
    #[error("blocker belongs to a different synthesis problem")]
    StaleProblem,
    #[error("blocker epoch is stale: expected {expected}, artifact has {artifact}")]
    StaleEpoch { expected: u64, artifact: u64 },
    #[error("typed blocker artifact is invalid: {0}")]
    InvalidArtifact(&'static str),
}

pub fn synthesis_problem_sha256(problem: &SynthesisProblem) -> Result<String, ProblemError> {
    problem.validate()?;
    let mut writer = CanonicalWriter::default();
    writer.text("noticer.quotient_forge.synthesis_problem_fingerprint.v1");
    writer.u32(problem.horizon);
    writer.u32(problem.machine_symbol_count);

    let mut private_classes = BTreeMap::<String, u64>::new();
    writer.len(problem.plant_states.len());
    for state in &problem.plant_states {
        writer.u32(state.id);
        writer.text(state.action_semantics.as_str());
        let private = state.private_history.as_str();
        let class = if let Some(class) = private_classes.get(private) {
            *class
        } else {
            let class = u64::try_from(private_classes.len()).unwrap_or(u64::MAX);
            private_classes.insert(private.to_owned(), class);
            class
        };
        writer.u64(class);
    }

    writer.len(problem.plant_transitions.len());
    for transition in &problem.plant_transitions {
        writer.u32(transition.from);
        writer.u32(transition.input);
        writer.u32(transition.to);
        writer.u32(transition.machine_symbol);
    }

    writer.len(problem.inputs.len());
    for input in &problem.inputs {
        writer.text(input.id.as_str());
        writer.text(&input.public_symbol);
        writer.optional_text(input.fault.as_ref().map(|fault| fault.as_str()));
    }

    writer.len(problem.semantics.len());
    for semantic in &problem.semantics {
        writer.text(semantic.id.as_str());
        writer.len(semantic.obligations.len());
        for obligation in &semantic.obligations {
            writer.text(obligation.id.as_str());
            writer.text(obligation.action.as_str());
            writer.u32(obligation.trigger_slot);
            writer.u32(obligation.deadline_slot);
        }
    }

    writer.len(problem.faults.len());
    for fault in &problem.faults {
        writer.text(fault.id.as_str());
        if let Some(recovery) = &fault.recovery {
            writer.bool(true);
            writer.text(recovery.action.as_str());
            writer.u32(recovery.deadline_after_slots);
        } else {
            writer.bool(false);
        }
    }

    writer.len(problem.observers.len());
    for observer in &problem.observers {
        writer.text(observer.id.as_str());
        writer.len(observer.visible_fields.len());
        for field in &observer.visible_fields {
            writer.text(field.as_str());
        }
        writer.bool(observer.observes_actions);
    }

    writer.len(problem.initial_pairs.len());
    for pair in &problem.initial_pairs {
        writer.u32(pair.left);
        writer.u32(pair.right);
    }

    writer.len(problem.outputs.len());
    for output in &problem.outputs {
        writer.bool(output.emitted);
        writer.len(output.fields.len());
        for (field, value) in &output.fields {
            writer.text(field.as_str());
            writer.text(value);
        }
        writer.len(output.actions.len());
        for action in &output.actions {
            write_obligation(&mut writer, &action.obligation);
            writer.text(action.action.as_str());
        }
    }
    Ok(sha256(&writer.bytes))
}

fn write_obligation(writer: &mut CanonicalWriter, obligation: &ObligationRef) {
    match obligation {
        ObligationRef::Authorized(id) => {
            writer.u32(0);
            writer.text(id.as_str());
        }
        ObligationRef::Recovery {
            fault,
            triggered_at,
        } => {
            writer.u32(1);
            writer.text(fault.as_str());
            writer.u32(*triggered_at);
        }
    }
}

fn blocker_digest(artifact: &TypedBlockerArtifact) -> Result<String, serde_json::Error> {
    let mut payload = artifact.clone();
    payload.blocker_sha256.clear();
    Ok(sha256(&serde_json::to_vec(&payload)?))
}

fn candidate_sha256(candidate: &ReleaseMachine) -> String {
    sha256(&candidate.canonical_bytes())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Default)]
struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn len(&mut self, value: usize) {
        self.u64(u64::try_from(value).unwrap_or(u64::MAX));
    }

    fn text(&mut self, value: &str) {
        self.len(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn optional_text(&mut self, value: Option<&str>) {
        self.bool(value.is_some());
        if let Some(value) = value {
            self.text(value);
        }
    }
}
