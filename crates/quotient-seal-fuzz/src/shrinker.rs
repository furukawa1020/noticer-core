use crate::{AdaptiveHostAction, AdaptiveHostProgram, FuzzCounterexample, FuzzViolationKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const SHRINK_REPORT_SCHEMA: &str = "quotient-seal.counterexample-shrink.v1";

const SHRINK_REPORT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_COUNTEREXAMPLE_SHRINK_V1";
const HARD_MAX_ACTIONS: u32 = 65_536;
const HARD_MAX_REPLAY_ATTEMPTS: u32 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckerRole {
    Primary,
    Secondary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayResult {
    Violation {
        kind: FuzzViolationKind,
        code: u16,
        public_witness_sha256: [u8; 32],
    },
    NoViolation,
    Unsupported {
        code: u16,
    },
    ResourceBound {
        code: u16,
    },
}

pub trait IndependentReplayChecker {
    fn replay(&mut self, program: &AdaptiveHostProgram) -> ReplayResult;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkBounds {
    pub max_actions: u32,
    pub max_replay_attempts: u32,
}

impl ShrinkBounds {
    pub fn validate(self) -> Result<(), ShrinkError> {
        if self.max_actions == 0
            || self.max_actions > HARD_MAX_ACTIONS
            || self.max_replay_attempts == 0
            || self.max_replay_attempts > HARD_MAX_REPLAY_ATTEMPTS
        {
            return Err(ShrinkError::InvalidBounds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShrinkPhase {
    InitialReplay,
    CallDeletion,
    InputSimplification,
    ContextReduction,
    FinalMinimality,
    FinalReplay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShrinkAttemptDecision {
    Accepted,
    Rejected,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkAttempt {
    pub index: u32,
    pub phase: ShrinkPhase,
    pub action_index: Option<u32>,
    pub before_action_count: u32,
    pub candidate_action_count: u32,
    pub candidate_program_sha256: [u8; 32],
    pub primary: ReplayResult,
    pub secondary: ReplayResult,
    pub decision: ShrinkAttemptDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShrinkInconclusiveReason {
    InitialNotReproduced,
    ReplayBound,
    CheckerDisagreement { attempt_index: u32 },
    Unsupported { checker: CheckerRole, code: u16 },
    ResourceBound { checker: CheckerRole, code: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShrinkVerdict {
    Reproduced { one_minimal: bool },
    Inconclusive { reason: ShrinkInconclusiveReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkReport {
    pub schema: String,
    pub seed: u64,
    pub bounds: ShrinkBounds,
    pub expected_kind: FuzzViolationKind,
    pub expected_code: u16,
    pub original_action_count: u32,
    pub original_program_sha256: [u8; 32],
    pub minimized_program: AdaptiveHostProgram,
    pub attempts: Vec<ShrinkAttempt>,
    pub verdict: ShrinkVerdict,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub artifact_sha256: [u8; 32],
}

impl ShrinkReport {
    fn build(
        original: &AdaptiveHostProgram,
        minimized_program: AdaptiveHostProgram,
        expected: FuzzCounterexample,
        bounds: ShrinkBounds,
        attempts: Vec<ShrinkAttempt>,
        verdict: ShrinkVerdict,
    ) -> Result<Self, ShrinkError> {
        let mut report = Self {
            schema: SHRINK_REPORT_SCHEMA.to_owned(),
            seed: original.seed,
            bounds,
            expected_kind: expected.kind,
            expected_code: expected.code,
            original_action_count: original.actions.len() as u32,
            original_program_sha256: original.artifact_sha256,
            minimized_program,
            attempts,
            verdict,
            evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            hardware_status: "NOT_VERIFIED".to_owned(),
            artifact_sha256: [0; 32],
        };
        report.artifact_sha256 = report.recomputed_sha256()?;
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), ShrinkError> {
        self.bounds.validate()?;
        self.minimized_program
            .validate()
            .map_err(|_| ShrinkError::ArtifactMismatch)?;
        if self.schema != SHRINK_REPORT_SCHEMA
            || self.evidence_origin != "INJECTED_TEST_FIXTURE"
            || self.hardware_status != "NOT_VERIFIED"
            || self.expected_code == 0
            || self.seed != self.minimized_program.seed
            || self.original_action_count == 0
            || self.original_action_count > self.bounds.max_actions
            || self.minimized_program.actions.is_empty()
            || self.minimized_program.actions.len() > self.original_action_count as usize
            || self.original_program_sha256 == [0; 32]
            || self.attempts.len() > self.bounds.max_replay_attempts as usize
        {
            return Err(ShrinkError::ArtifactMismatch);
        }
        for (index, attempt) in self.attempts.iter().enumerate() {
            if attempt.index != index as u32
                || attempt.before_action_count == 0
                || attempt.candidate_action_count == 0
                || attempt.candidate_program_sha256 == [0; 32]
                || attempt.candidate_action_count > self.bounds.max_actions
            {
                return Err(ShrinkError::ArtifactMismatch);
            }
        }
        match self.verdict {
            ShrinkVerdict::Reproduced { one_minimal: true } => {
                let Some(last) = self.attempts.last() else {
                    return Err(ShrinkError::ArtifactMismatch);
                };
                if last.phase != ShrinkPhase::FinalReplay
                    || last.decision != ShrinkAttemptDecision::Accepted
                    || last.candidate_program_sha256 != self.minimized_program.artifact_sha256
                {
                    return Err(ShrinkError::ArtifactMismatch);
                }
            }
            ShrinkVerdict::Reproduced { one_minimal: false } => {
                return Err(ShrinkError::ArtifactMismatch);
            }
            ShrinkVerdict::Inconclusive { .. } => {}
        }
        if self.artifact_sha256 != self.recomputed_sha256()? {
            return Err(ShrinkError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ShrinkError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ShrinkError::Json)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], ShrinkError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| ShrinkError::Json)?;
        Ok(domain_hash(SHRINK_REPORT_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShrinkError {
    #[error("counterexample shrink bounds are invalid")]
    InvalidBounds,
    #[error("counterexample shrink input is invalid")]
    InvalidInput,
    #[error("counterexample shrink internal contract failed")]
    InternalContract,
    #[error("counterexample shrink report failed full recomputation")]
    ArtifactMismatch,
    #[error("counterexample shrink JSON serialization failed")]
    Json,
}

#[derive(Clone, Copy)]
enum Evaluation {
    Preserve,
    Reject,
    Stop(ShrinkInconclusiveReason),
}

pub fn shrink_counterexample<P: IndependentReplayChecker, S: IndependentReplayChecker>(
    original: &AdaptiveHostProgram,
    expected: FuzzCounterexample,
    bounds: ShrinkBounds,
    primary: &mut P,
    secondary: &mut S,
) -> Result<ShrinkReport, ShrinkError> {
    bounds.validate()?;
    original.validate().map_err(|_| ShrinkError::InvalidInput)?;
    if original.actions.len() > bounds.max_actions as usize
        || expected.code == 0
        || expected.public_witness_sha256 == [0; 32]
    {
        return Err(ShrinkError::InvalidInput);
    }
    let mut current = original.clone();
    let mut attempts = Vec::new();
    match evaluate(
        original,
        original.actions.len() as u32,
        ShrinkPhase::InitialReplay,
        None,
        expected,
        bounds,
        &mut attempts,
        primary,
        secondary,
    ) {
        Evaluation::Preserve => {}
        Evaluation::Reject => {
            return report(
                original,
                current,
                expected,
                bounds,
                attempts,
                ShrinkInconclusiveReason::InitialNotReproduced,
            );
        }
        Evaluation::Stop(reason) => {
            return report(original, current, expected, bounds, attempts, reason);
        }
    }

    if let Err(reason) = delete_fixed_point(
        &mut current,
        ShrinkPhase::CallDeletion,
        expected,
        bounds,
        &mut attempts,
        primary,
        secondary,
    ) {
        return report(original, current, expected, bounds, attempts, reason);
    }
    if let Err(reason) = simplify_actions(
        &mut current,
        ShrinkPhase::InputSimplification,
        expected,
        bounds,
        &mut attempts,
        primary,
        secondary,
        simplify_input,
    ) {
        return report(original, current, expected, bounds, attempts, reason);
    }
    if let Err(reason) = simplify_actions(
        &mut current,
        ShrinkPhase::ContextReduction,
        expected,
        bounds,
        &mut attempts,
        primary,
        secondary,
        simplify_context,
    ) {
        return report(original, current, expected, bounds, attempts, reason);
    }
    if let Err(reason) = delete_fixed_point(
        &mut current,
        ShrinkPhase::FinalMinimality,
        expected,
        bounds,
        &mut attempts,
        primary,
        secondary,
    ) {
        return report(original, current, expected, bounds, attempts, reason);
    }
    match evaluate(
        &current,
        current.actions.len() as u32,
        ShrinkPhase::FinalReplay,
        None,
        expected,
        bounds,
        &mut attempts,
        primary,
        secondary,
    ) {
        Evaluation::Preserve => ShrinkReport::build(
            original,
            current,
            expected,
            bounds,
            attempts,
            ShrinkVerdict::Reproduced { one_minimal: true },
        ),
        Evaluation::Reject => report(
            original,
            current,
            expected,
            bounds,
            attempts,
            ShrinkInconclusiveReason::InitialNotReproduced,
        ),
        Evaluation::Stop(reason) => report(original, current, expected, bounds, attempts, reason),
    }
}

fn delete_fixed_point<P: IndependentReplayChecker, S: IndependentReplayChecker>(
    current: &mut AdaptiveHostProgram,
    phase: ShrinkPhase,
    expected: FuzzCounterexample,
    bounds: ShrinkBounds,
    attempts: &mut Vec<ShrinkAttempt>,
    primary: &mut P,
    secondary: &mut S,
) -> Result<(), ShrinkInconclusiveReason> {
    let mut index = 0;
    while current.actions.len() > 1 && index < current.actions.len() {
        let before_count = current.actions.len() as u32;
        let mut actions = current.actions.clone();
        actions.remove(index);
        let candidate =
            rebuild(current, actions).map_err(|_| ShrinkInconclusiveReason::Unsupported {
                checker: CheckerRole::Primary,
                code: u16::MAX,
            })?;
        match evaluate(
            &candidate,
            before_count,
            phase,
            Some(index as u32),
            expected,
            bounds,
            attempts,
            primary,
            secondary,
        ) {
            Evaluation::Preserve => {
                *current = candidate;
                index = 0;
            }
            Evaluation::Reject => index += 1,
            Evaluation::Stop(reason) => return Err(reason),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn simplify_actions<P, S>(
    current: &mut AdaptiveHostProgram,
    phase: ShrinkPhase,
    expected: FuzzCounterexample,
    bounds: ShrinkBounds,
    attempts: &mut Vec<ShrinkAttempt>,
    primary: &mut P,
    secondary: &mut S,
    simplify: fn(AdaptiveHostAction) -> Option<AdaptiveHostAction>,
) -> Result<(), ShrinkInconclusiveReason>
where
    P: IndependentReplayChecker,
    S: IndependentReplayChecker,
{
    for index in 0..current.actions.len() {
        let Some(action) = simplify(current.actions[index]) else {
            continue;
        };
        let mut actions = current.actions.clone();
        actions[index] = action;
        let candidate =
            rebuild(current, actions).map_err(|_| ShrinkInconclusiveReason::Unsupported {
                checker: CheckerRole::Primary,
                code: u16::MAX,
            })?;
        match evaluate(
            &candidate,
            current.actions.len() as u32,
            phase,
            Some(index as u32),
            expected,
            bounds,
            attempts,
            primary,
            secondary,
        ) {
            Evaluation::Preserve => *current = candidate,
            Evaluation::Reject => {}
            Evaluation::Stop(reason) => return Err(reason),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate<P: IndependentReplayChecker, S: IndependentReplayChecker>(
    candidate: &AdaptiveHostProgram,
    before_action_count: u32,
    phase: ShrinkPhase,
    action_index: Option<u32>,
    expected: FuzzCounterexample,
    bounds: ShrinkBounds,
    attempts: &mut Vec<ShrinkAttempt>,
    primary: &mut P,
    secondary: &mut S,
) -> Evaluation {
    if attempts.len() >= bounds.max_replay_attempts as usize {
        return Evaluation::Stop(ShrinkInconclusiveReason::ReplayBound);
    }
    let primary_result = primary.replay(candidate);
    let secondary_result = secondary.replay(candidate);
    let index = attempts.len() as u32;
    let evaluation = classify(primary_result, secondary_result, expected, index);
    let decision = match evaluation {
        Evaluation::Preserve => ShrinkAttemptDecision::Accepted,
        Evaluation::Reject => ShrinkAttemptDecision::Rejected,
        Evaluation::Stop(_) => ShrinkAttemptDecision::Inconclusive,
    };
    attempts.push(ShrinkAttempt {
        index,
        phase,
        action_index,
        before_action_count,
        candidate_action_count: candidate.actions.len() as u32,
        candidate_program_sha256: candidate.artifact_sha256,
        primary: primary_result,
        secondary: secondary_result,
        decision,
    });
    evaluation
}

fn classify(
    primary: ReplayResult,
    secondary: ReplayResult,
    expected: FuzzCounterexample,
    attempt_index: u32,
) -> Evaluation {
    if let Some(reason) = terminal_result(primary, CheckerRole::Primary) {
        return Evaluation::Stop(reason);
    }
    if let Some(reason) = terminal_result(secondary, CheckerRole::Secondary) {
        return Evaluation::Stop(reason);
    }
    match (primary, secondary) {
        (
            ReplayResult::Violation {
                kind: left_kind,
                code: left_code,
                ..
            },
            ReplayResult::Violation {
                kind: right_kind,
                code: right_code,
                ..
            },
        ) if left_kind == right_kind && left_code == right_code => {
            if left_kind == expected.kind && left_code == expected.code {
                Evaluation::Preserve
            } else {
                Evaluation::Reject
            }
        }
        (ReplayResult::NoViolation, ReplayResult::NoViolation) => Evaluation::Reject,
        _ => Evaluation::Stop(ShrinkInconclusiveReason::CheckerDisagreement { attempt_index }),
    }
}

fn terminal_result(result: ReplayResult, checker: CheckerRole) -> Option<ShrinkInconclusiveReason> {
    match result {
        ReplayResult::Unsupported { code } => {
            Some(ShrinkInconclusiveReason::Unsupported { checker, code })
        }
        ReplayResult::ResourceBound { code } => {
            Some(ShrinkInconclusiveReason::ResourceBound { checker, code })
        }
        ReplayResult::Violation { .. } | ReplayResult::NoViolation => None,
    }
}

fn simplify_input(action: AdaptiveHostAction) -> Option<AdaptiveHostAction> {
    match action {
        AdaptiveHostAction::Tick { public_slot } if public_slot != 0 => {
            Some(AdaptiveHostAction::Tick { public_slot: 0 })
        }
        AdaptiveHostAction::Malformed { payload_tag } if payload_tag != 0 => {
            Some(AdaptiveHostAction::Malformed { payload_tag: 0 })
        }
        AdaptiveHostAction::Repeat { count } if count != 1 => {
            Some(AdaptiveHostAction::Repeat { count: 1 })
        }
        AdaptiveHostAction::StaleSlot { delta } if delta != 1 => {
            Some(AdaptiveHostAction::StaleSlot { delta: 1 })
        }
        AdaptiveHostAction::FutureSlot { delta } if delta != 1 => {
            Some(AdaptiveHostAction::FutureSlot { delta: 1 })
        }
        AdaptiveHostAction::Fault { code } if code != 1 => {
            Some(AdaptiveHostAction::Fault { code: 1 })
        }
        _ => None,
    }
}

fn simplify_context(action: AdaptiveHostAction) -> Option<AdaptiveHostAction> {
    match action {
        AdaptiveHostAction::Reset { epoch } if epoch != 0 => {
            Some(AdaptiveHostAction::Reset { epoch: 0 })
        }
        AdaptiveHostAction::Handoff { service_alias } if service_alias != 0 => {
            Some(AdaptiveHostAction::Handoff { service_alias: 0 })
        }
        AdaptiveHostAction::Reconnect { service_alias } if service_alias != 0 => {
            Some(AdaptiveHostAction::Reconnect { service_alias: 0 })
        }
        AdaptiveHostAction::ServiceSwitch { from, to } if from != 0 || to != 1 => {
            Some(AdaptiveHostAction::ServiceSwitch { from: 0, to: 1 })
        }
        _ => None,
    }
}

fn rebuild(
    source: &AdaptiveHostProgram,
    actions: Vec<AdaptiveHostAction>,
) -> Result<AdaptiveHostProgram, ShrinkError> {
    AdaptiveHostProgram::build(source.seed, source.bounds, actions)
        .map_err(|_| ShrinkError::InternalContract)
}

fn report(
    original: &AdaptiveHostProgram,
    current: AdaptiveHostProgram,
    expected: FuzzCounterexample,
    bounds: ShrinkBounds,
    attempts: Vec<ShrinkAttempt>,
    reason: ShrinkInconclusiveReason,
) -> Result<ShrinkReport, ShrinkError> {
    ShrinkReport::build(
        original,
        current,
        expected,
        bounds,
        attempts,
        ShrinkVerdict::Inconclusive { reason },
    )
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
