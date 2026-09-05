//! Deterministic incremental CEGIS orchestration.
//!
//! This module owns lifecycle and audit semantics. Solver-specific incremental
//! state remains behind [`IncrementalAssertionBackend`], while candidate
//! validation remains behind [`CandidateChecker`].

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::BlockerClass;

pub const INCREMENTAL_CEGIS_SESSION_SCHEMA_V1: &str =
    "noticer.quotient_forge.incremental_cegis_session.v1";
pub const SESSION_BLOCKER_SCHEMA_V1: &str = "noticer.quotient_forge.session_blocker.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionBlockerClass {
    Security,
    Utility,
    Fault,
}

impl From<BlockerClass> for SessionBlockerClass {
    fn from(value: BlockerClass) -> Self {
        match value {
            BlockerClass::Security => Self::Security,
            BlockerClass::Utility => Self::Utility,
            BlockerClass::Fault => Self::Fault,
        }
    }
}

/// Public, value-redacted assertion reference replayed by an incremental backend.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionBlocker {
    pub schema_version: String,
    pub blocker_sha256: String,
    pub class: SessionBlockerClass,
    pub typed_blocker_artifact_sha256: String,
    pub source_candidate_sha256: String,
    pub counterexample_signature_sha256: String,
    pub assertion_sha256: String,
    pub subsumes_blocker_sha256: Vec<String>,
}

impl SessionBlocker {
    pub fn new(
        class: impl Into<SessionBlockerClass>,
        typed_blocker_artifact_sha256: impl Into<String>,
        source_candidate_sha256: impl Into<String>,
        counterexample_signature_sha256: impl Into<String>,
        assertion_sha256: impl Into<String>,
        mut subsumes_blocker_sha256: Vec<String>,
    ) -> Result<Self, SessionInputError> {
        subsumes_blocker_sha256.sort();
        subsumes_blocker_sha256.dedup();
        let mut blocker = Self {
            schema_version: SESSION_BLOCKER_SCHEMA_V1.to_owned(),
            blocker_sha256: String::new(),
            class: class.into(),
            typed_blocker_artifact_sha256: typed_blocker_artifact_sha256.into(),
            source_candidate_sha256: source_candidate_sha256.into(),
            counterexample_signature_sha256: counterexample_signature_sha256.into(),
            assertion_sha256: assertion_sha256.into(),
            subsumes_blocker_sha256,
        };
        blocker.validate_payload()?;
        blocker.blocker_sha256 = blocker.digest()?;
        Ok(blocker)
    }

    pub fn validate(&self) -> Result<(), SessionInputError> {
        self.validate_payload()?;
        require_sha256("blocker_sha256", &self.blocker_sha256)?;
        if self.digest()? != self.blocker_sha256 {
            return Err(SessionInputError::DigestMismatch("blocker_sha256"));
        }
        Ok(())
    }

    fn validate_payload(&self) -> Result<(), SessionInputError> {
        if self.schema_version != SESSION_BLOCKER_SCHEMA_V1 {
            return Err(SessionInputError::SchemaVersion);
        }
        require_sha256(
            "typed_blocker_artifact_sha256",
            &self.typed_blocker_artifact_sha256,
        )?;
        require_sha256("source_candidate_sha256", &self.source_candidate_sha256)?;
        require_sha256(
            "counterexample_signature_sha256",
            &self.counterexample_signature_sha256,
        )?;
        require_sha256("assertion_sha256", &self.assertion_sha256)?;
        if self
            .subsumes_blocker_sha256
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(SessionInputError::NonCanonicalBlocker);
        }
        for digest in &self.subsumes_blocker_sha256 {
            require_sha256("subsumes_blocker_sha256", digest)?;
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, SessionInputError> {
        let mut payload = self.clone();
        payload.blocker_sha256.clear();
        canonical_json_sha256(&payload)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionContext {
    pub problem_sha256: String,
    pub epoch: u64,
    pub seed: u64,
}

impl SessionContext {
    pub fn validate(&self) -> Result<(), SessionInputError> {
        require_sha256("problem_sha256", &self.problem_sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RestartPolicy {
    pub accepted_blockers_per_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionConfig {
    pub max_candidates: u64,
    pub restart_policy: RestartPolicy,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_candidates: 1_000,
            restart_policy: RestartPolicy {
                accepted_blockers_per_generation: 32,
            },
        }
    }
}

impl SessionConfig {
    fn validate(&self) -> Result<(), SessionInputError> {
        if self.max_candidates == 0 {
            return Err(SessionInputError::InvalidConfig("max_candidates"));
        }
        if self.restart_policy.accepted_blockers_per_generation == 0 {
            return Err(SessionInputError::InvalidConfig(
                "accepted_blockers_per_generation",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionInconclusiveReason {
    Timeout,
    ResourceExhausted,
    SolverUnavailable,
    ProcessFailure,
    CheckerInconclusive,
    CandidateLimit,
    InvalidBlocker,
    NoProgress,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum SessionOutcome {
    Sat { candidate_sha256: String },
    Unsat,
    Inconclusive { reason: SessionInconclusiveReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolverFailure {
    Unavailable,
    SpawnFailed,
    ProcessExited,
    ProtocolViolation,
}

pub enum BackendDecision<Candidate> {
    Candidate {
        candidate_sha256: String,
        candidate: Candidate,
    },
    Unsat,
    Inconclusive {
        reason: SessionInconclusiveReason,
    },
}

pub enum CheckerDecision {
    Verified,
    Rejected { blocker: SessionBlocker },
    Inconclusive { reason: SessionInconclusiveReason },
}

pub trait IncrementalAssertionBackend {
    type Candidate;

    fn start(&mut self, context: &SessionContext) -> Result<(), SolverFailure>;
    fn push_blocker(&mut self, blocker: &SessionBlocker) -> Result<(), SolverFailure>;
    fn solve(&mut self) -> Result<BackendDecision<Self::Candidate>, SolverFailure>;
}

pub trait CandidateChecker<Candidate> {
    fn check(&mut self, candidate_sha256: &str, candidate: &Candidate) -> CheckerDecision;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEventKind {
    SessionStarted,
    BlockerAccepted,
    BlockerDuplicate,
    BlockerSubsumed,
    BackendStarted,
    BlockerPushed,
    SolveCalled,
    CandidateChecked,
    Restarted,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionEvent {
    pub sequence: u64,
    pub generation: u64,
    pub kind: SessionEventKind,
    pub blocker_sha256: Option<String>,
    pub candidate_sha256: Option<String>,
    pub replayed_blockers: Option<u64>,
    pub reason: Option<SessionInconclusiveReason>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionMetrics {
    pub backend_starts: u64,
    pub solver_calls: u64,
    pub candidates: u64,
    pub checker_calls: u64,
    pub blocker_pushes: u64,
    pub accepted_blockers: u64,
    pub duplicate_blockers: u64,
    pub subsumed_blockers: u64,
    pub restarts: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverReuseAudit {
    pub backend_generations: u64,
    pub replayed_pushes: u64,
    pub incremental_pushes: u64,
    pub reused_solve_calls: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionArtifact {
    pub schema_version: String,
    pub problem_sha256: String,
    pub epoch: u64,
    pub seed: u64,
    pub config: SessionConfig,
    pub outcome: SessionOutcome,
    pub blockers: Vec<SessionBlocker>,
    pub transcript: Vec<SessionEvent>,
    pub metrics: SessionMetrics,
    pub reuse_audit: SolverReuseAudit,
    pub artifact_sha256: String,
}

impl SessionArtifact {
    pub fn validate(&self) -> Result<(), SessionInputError> {
        if self.schema_version != INCREMENTAL_CEGIS_SESSION_SCHEMA_V1 {
            return Err(SessionInputError::SchemaVersion);
        }
        require_sha256("problem_sha256", &self.problem_sha256)?;
        require_sha256("artifact_sha256", &self.artifact_sha256)?;
        self.config.validate()?;
        if self
            .blockers
            .windows(2)
            .any(|pair| compare_blockers(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(SessionInputError::NonCanonicalBlocker);
        }
        for blocker in &self.blockers {
            blocker.validate()?;
        }
        if self
            .transcript
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence != index as u64)
        {
            return Err(SessionInputError::NonCanonicalTranscript);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(SessionInputError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SessionInputError {
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("{0} must be greater than zero")]
    InvalidConfig(&'static str),
    #[error("blocker order or subsumption list is not canonical")]
    NonCanonicalBlocker,
    #[error("session transcript sequence is not canonical")]
    NonCanonicalTranscript,
    #[error("{0} does not match its canonical payload")]
    DigestMismatch(&'static str),
    #[error("canonical artifact serialization failed")]
    Serialization,
}

pub fn run_incremental_cegis<Backend, Checker>(
    backend: &mut Backend,
    checker: &mut Checker,
    context: SessionContext,
    config: SessionConfig,
    mut initial_blockers: Vec<SessionBlocker>,
) -> Result<SessionArtifact, SessionInputError>
where
    Backend: IncrementalAssertionBackend,
    Checker: CandidateChecker<Backend::Candidate>,
{
    context.validate()?;
    config.validate()?;
    for blocker in &initial_blockers {
        blocker.validate()?;
    }
    initial_blockers.sort_by(compare_blockers);

    let mut blockers = Vec::new();
    let mut transcript = Vec::new();
    let mut metrics = SessionMetrics::default();
    let mut reuse_audit = SolverReuseAudit::default();
    let mut generation = 0;
    record_event(
        &mut transcript,
        generation,
        SessionEventKind::SessionStarted,
        None,
        None,
        None,
        None,
    );

    for blocker in initial_blockers {
        match insert_blocker(&mut blockers, blocker)? {
            InsertDisposition::Accepted {
                blocker_sha256,
                superseded,
                ..
            } => {
                for digest in superseded {
                    metrics.subsumed_blockers += 1;
                    record_event(
                        &mut transcript,
                        generation,
                        SessionEventKind::BlockerSubsumed,
                        Some(digest),
                        None,
                        None,
                        None,
                    );
                }
                metrics.accepted_blockers += 1;
                record_event(
                    &mut transcript,
                    generation,
                    SessionEventKind::BlockerAccepted,
                    Some(blocker_sha256),
                    None,
                    None,
                    None,
                );
            }
            InsertDisposition::Duplicate { blocker_sha256 } => {
                metrics.duplicate_blockers += 1;
                record_event(
                    &mut transcript,
                    generation,
                    SessionEventKind::BlockerDuplicate,
                    Some(blocker_sha256),
                    None,
                    None,
                    None,
                );
            }
            InsertDisposition::Subsumed { blocker_sha256 } => {
                metrics.subsumed_blockers += 1;
                record_event(
                    &mut transcript,
                    generation,
                    SessionEventKind::BlockerSubsumed,
                    Some(blocker_sha256),
                    None,
                    None,
                    None,
                );
            }
        }
    }

    if let Err(failure) = start_generation(
        backend,
        &context,
        generation,
        &blockers,
        &mut transcript,
        &mut metrics,
        &mut reuse_audit,
    ) {
        return finalize_artifact(
            &context,
            &config,
            &blockers,
            &mut transcript,
            generation,
            &metrics,
            &reuse_audit,
            SessionOutcome::Inconclusive {
                reason: failure_reason(failure),
            },
        );
    }

    let mut accepted_since_restart = 0_u64;
    let mut solves_in_generation = 0_u64;
    loop {
        if metrics.candidates >= config.max_candidates {
            return finalize_artifact(
                &context,
                &config,
                &blockers,
                &mut transcript,
                generation,
                &metrics,
                &reuse_audit,
                SessionOutcome::Inconclusive {
                    reason: SessionInconclusiveReason::CandidateLimit,
                },
            );
        }

        metrics.solver_calls += 1;
        if solves_in_generation > 0 {
            reuse_audit.reused_solve_calls += 1;
        }
        solves_in_generation += 1;
        record_event(
            &mut transcript,
            generation,
            SessionEventKind::SolveCalled,
            None,
            None,
            None,
            None,
        );
        let decision = match backend.solve() {
            Ok(decision) => decision,
            Err(failure) => {
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Inconclusive {
                        reason: failure_reason(failure),
                    },
                );
            }
        };

        let (candidate_sha256, candidate) = match decision {
            BackendDecision::Unsat => {
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Unsat,
                );
            }
            BackendDecision::Inconclusive { reason } => {
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Inconclusive { reason },
                );
            }
            BackendDecision::Candidate {
                candidate_sha256,
                candidate,
            } => (candidate_sha256, candidate),
        };

        if require_sha256("candidate_sha256", &candidate_sha256).is_err() {
            return finalize_artifact(
                &context,
                &config,
                &blockers,
                &mut transcript,
                generation,
                &metrics,
                &reuse_audit,
                SessionOutcome::Inconclusive {
                    reason: SessionInconclusiveReason::ProcessFailure,
                },
            );
        }
        metrics.candidates += 1;
        metrics.checker_calls += 1;
        record_event(
            &mut transcript,
            generation,
            SessionEventKind::CandidateChecked,
            None,
            Some(candidate_sha256.clone()),
            None,
            None,
        );

        let blocker = match checker.check(&candidate_sha256, &candidate) {
            CheckerDecision::Verified => {
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Sat { candidate_sha256 },
                );
            }
            CheckerDecision::Inconclusive { reason } => {
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Inconclusive { reason },
                );
            }
            CheckerDecision::Rejected { blocker } => blocker,
        };

        if blocker.validate().is_err() || blocker.source_candidate_sha256 != candidate_sha256 {
            return finalize_artifact(
                &context,
                &config,
                &blockers,
                &mut transcript,
                generation,
                &metrics,
                &reuse_audit,
                SessionOutcome::Inconclusive {
                    reason: SessionInconclusiveReason::InvalidBlocker,
                },
            );
        }

        let disposition = insert_blocker(&mut blockers, blocker)?;
        let canonical_replay_required = match disposition {
            InsertDisposition::Duplicate { blocker_sha256 } => {
                metrics.duplicate_blockers += 1;
                record_event(
                    &mut transcript,
                    generation,
                    SessionEventKind::BlockerDuplicate,
                    Some(blocker_sha256),
                    None,
                    None,
                    None,
                );
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Inconclusive {
                        reason: SessionInconclusiveReason::NoProgress,
                    },
                );
            }
            InsertDisposition::Subsumed { blocker_sha256 } => {
                metrics.subsumed_blockers += 1;
                record_event(
                    &mut transcript,
                    generation,
                    SessionEventKind::BlockerSubsumed,
                    Some(blocker_sha256),
                    None,
                    None,
                    None,
                );
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Inconclusive {
                        reason: SessionInconclusiveReason::NoProgress,
                    },
                );
            }
            InsertDisposition::Accepted {
                blocker_sha256,
                superseded,
                canonical_replay_required,
            } => {
                for digest in superseded {
                    metrics.subsumed_blockers += 1;
                    record_event(
                        &mut transcript,
                        generation,
                        SessionEventKind::BlockerSubsumed,
                        Some(digest),
                        None,
                        None,
                        None,
                    );
                }
                metrics.accepted_blockers += 1;
                record_event(
                    &mut transcript,
                    generation,
                    SessionEventKind::BlockerAccepted,
                    Some(blocker_sha256),
                    None,
                    None,
                    None,
                );
                canonical_replay_required
            }
        };

        accepted_since_restart += 1;
        let policy_restart =
            accepted_since_restart >= config.restart_policy.accepted_blockers_per_generation;
        if canonical_replay_required || policy_restart {
            metrics.restarts += 1;
            generation += 1;
            record_event(
                &mut transcript,
                generation,
                SessionEventKind::Restarted,
                None,
                None,
                Some(blockers.len() as u64),
                None,
            );
            if let Err(failure) = start_generation(
                backend,
                &context,
                generation,
                &blockers,
                &mut transcript,
                &mut metrics,
                &mut reuse_audit,
            ) {
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Inconclusive {
                        reason: failure_reason(failure),
                    },
                );
            }
            accepted_since_restart = 0;
            solves_in_generation = 0;
        } else {
            let blocker = blockers
                .last()
                .expect("an accepted blocker must remain in the canonical set");
            if let Err(failure) = backend.push_blocker(blocker) {
                return finalize_artifact(
                    &context,
                    &config,
                    &blockers,
                    &mut transcript,
                    generation,
                    &metrics,
                    &reuse_audit,
                    SessionOutcome::Inconclusive {
                        reason: failure_reason(failure),
                    },
                );
            }
            metrics.blocker_pushes += 1;
            reuse_audit.incremental_pushes += 1;
            record_event(
                &mut transcript,
                generation,
                SessionEventKind::BlockerPushed,
                Some(blocker.blocker_sha256.clone()),
                None,
                None,
                None,
            );
        }
    }
}

enum InsertDisposition {
    Accepted {
        blocker_sha256: String,
        superseded: Vec<String>,
        canonical_replay_required: bool,
    },
    Duplicate {
        blocker_sha256: String,
    },
    Subsumed {
        blocker_sha256: String,
    },
}

fn insert_blocker(
    blockers: &mut Vec<SessionBlocker>,
    blocker: SessionBlocker,
) -> Result<InsertDisposition, SessionInputError> {
    blocker.validate()?;
    if blockers
        .iter()
        .any(|existing| existing.blocker_sha256 == blocker.blocker_sha256)
    {
        return Ok(InsertDisposition::Duplicate {
            blocker_sha256: blocker.blocker_sha256,
        });
    }
    if blockers.iter().any(|existing| {
        existing
            .subsumes_blocker_sha256
            .binary_search(&blocker.blocker_sha256)
            .is_ok()
    }) {
        return Ok(InsertDisposition::Subsumed {
            blocker_sha256: blocker.blocker_sha256,
        });
    }

    let canonical_replay_required = blockers
        .last()
        .is_some_and(|last| compare_blockers(last, &blocker) != Ordering::Less);
    let superseded = blockers
        .iter()
        .filter(|existing| {
            blocker
                .subsumes_blocker_sha256
                .binary_search(&existing.blocker_sha256)
                .is_ok()
        })
        .map(|existing| existing.blocker_sha256.clone())
        .collect::<Vec<_>>();
    blockers.retain(|existing| !superseded.contains(&existing.blocker_sha256));
    let blocker_sha256 = blocker.blocker_sha256.clone();
    blockers.push(blocker);
    blockers.sort_by(compare_blockers);
    Ok(InsertDisposition::Accepted {
        blocker_sha256,
        canonical_replay_required: canonical_replay_required || !superseded.is_empty(),
        superseded,
    })
}

fn compare_blockers(left: &SessionBlocker, right: &SessionBlocker) -> Ordering {
    (
        left.class,
        &left.counterexample_signature_sha256,
        &left.assertion_sha256,
        &left.blocker_sha256,
    )
        .cmp(&(
            right.class,
            &right.counterexample_signature_sha256,
            &right.assertion_sha256,
            &right.blocker_sha256,
        ))
}

fn start_generation<Backend: IncrementalAssertionBackend>(
    backend: &mut Backend,
    context: &SessionContext,
    generation: u64,
    blockers: &[SessionBlocker],
    transcript: &mut Vec<SessionEvent>,
    metrics: &mut SessionMetrics,
    reuse_audit: &mut SolverReuseAudit,
) -> Result<(), SolverFailure> {
    metrics.backend_starts += 1;
    backend.start(context)?;
    reuse_audit.backend_generations += 1;
    record_event(
        transcript,
        generation,
        SessionEventKind::BackendStarted,
        None,
        None,
        Some(blockers.len() as u64),
        None,
    );
    for blocker in blockers {
        backend.push_blocker(blocker)?;
        metrics.blocker_pushes += 1;
        reuse_audit.replayed_pushes += 1;
        record_event(
            transcript,
            generation,
            SessionEventKind::BlockerPushed,
            Some(blocker.blocker_sha256.clone()),
            None,
            None,
            None,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_event(
    transcript: &mut Vec<SessionEvent>,
    generation: u64,
    kind: SessionEventKind,
    blocker_sha256: Option<String>,
    candidate_sha256: Option<String>,
    replayed_blockers: Option<u64>,
    reason: Option<SessionInconclusiveReason>,
) {
    transcript.push(SessionEvent {
        sequence: transcript.len() as u64,
        generation,
        kind,
        blocker_sha256,
        candidate_sha256,
        replayed_blockers,
        reason,
    });
}

#[allow(clippy::too_many_arguments)]
fn finalize_artifact(
    context: &SessionContext,
    config: &SessionConfig,
    blockers: &[SessionBlocker],
    transcript: &mut Vec<SessionEvent>,
    generation: u64,
    metrics: &SessionMetrics,
    reuse_audit: &SolverReuseAudit,
    outcome: SessionOutcome,
) -> Result<SessionArtifact, SessionInputError> {
    let (candidate_sha256, reason) = match &outcome {
        SessionOutcome::Sat { candidate_sha256 } => (Some(candidate_sha256.clone()), None),
        SessionOutcome::Unsat => (None, None),
        SessionOutcome::Inconclusive { reason } => (None, Some(*reason)),
    };
    record_event(
        transcript,
        generation,
        SessionEventKind::Completed,
        None,
        candidate_sha256,
        None,
        reason,
    );
    let mut artifact = SessionArtifact {
        schema_version: INCREMENTAL_CEGIS_SESSION_SCHEMA_V1.to_owned(),
        problem_sha256: context.problem_sha256.clone(),
        epoch: context.epoch,
        seed: context.seed,
        config: config.clone(),
        outcome,
        blockers: blockers.to_vec(),
        transcript: transcript.clone(),
        metrics: metrics.clone(),
        reuse_audit: reuse_audit.clone(),
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate()?;
    Ok(artifact)
}

fn failure_reason(failure: SolverFailure) -> SessionInconclusiveReason {
    match failure {
        SolverFailure::Unavailable => SessionInconclusiveReason::SolverUnavailable,
        SolverFailure::SpawnFailed
        | SolverFailure::ProcessExited
        | SolverFailure::ProtocolViolation => SessionInconclusiveReason::ProcessFailure,
    }
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), SessionInputError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(SessionInputError::InvalidSha256(field))
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, SessionInputError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SessionInputError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
