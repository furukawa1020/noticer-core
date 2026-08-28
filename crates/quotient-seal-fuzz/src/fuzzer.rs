use crate::{
    apply_public_feedback, AdaptiveContextBounds, AdaptiveContextState, AdaptiveHostAction,
    AdaptiveHostProgram, AdaptiveProgramError, AdaptivePublicObservation, CorpusBounds,
    CorpusEntry, CoverageError, CoverageFeedback, DeterministicCorpus, PublicCoverageSnapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const ADAPTIVE_FUZZ_REPORT_SCHEMA: &str = "quotient-seal.adaptive-fuzz-report.v1";

const SELECTOR_DOMAIN: &[u8] = b"QUOTIENT_SEAL_ADAPTIVE_FUZZ_SELECTOR_V1";
const PARAMETER_DOMAIN: &[u8] = b"QUOTIENT_SEAL_ADAPTIVE_FUZZ_PARAMETER_V1";
const RANDOMNESS_DOMAIN: &[u8] = b"QUOTIENT_SEAL_ADAPTIVE_FUZZ_RANDOMNESS_V1";
const REPORT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_ADAPTIVE_FUZZ_REPORT_V1";
const HARD_MAX_STEPS: u32 = 65_536;
const HARD_MAX_STATES: u32 = 65_536;
const HARD_MAX_LOGICAL_TIME: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdaptiveActionClass {
    Tick = 0,
    Reset = 1,
    Handoff = 2,
    Malformed = 3,
    Repeat = 4,
    StaleSlot = 5,
    FutureSlot = 6,
    Fault = 7,
    Reconnect = 8,
    ServiceSwitch = 9,
}

impl AdaptiveActionClass {
    pub const ALL: [Self; 10] = [
        Self::Tick,
        Self::Reset,
        Self::Handoff,
        Self::Malformed,
        Self::Repeat,
        Self::StaleSlot,
        Self::FutureSlot,
        Self::Fault,
        Self::Reconnect,
        Self::ServiceSwitch,
    ];

    #[must_use]
    pub const fn of(action: AdaptiveHostAction) -> Self {
        match action {
            AdaptiveHostAction::Tick { .. } => Self::Tick,
            AdaptiveHostAction::Reset { .. } => Self::Reset,
            AdaptiveHostAction::Handoff { .. } => Self::Handoff,
            AdaptiveHostAction::Malformed { .. } => Self::Malformed,
            AdaptiveHostAction::Repeat { .. } => Self::Repeat,
            AdaptiveHostAction::StaleSlot { .. } => Self::StaleSlot,
            AdaptiveHostAction::FutureSlot { .. } => Self::FutureSlot,
            AdaptiveHostAction::Fault { .. } => Self::Fault,
            AdaptiveHostAction::Reconnect { .. } => Self::Reconnect,
            AdaptiveHostAction::ServiceSwitch { .. } => Self::ServiceSwitch,
        }
    }

    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FuzzViolationKind {
    ObserverTraceDivergence,
    UtilityViolation,
    ContextViolation,
    ReleasePolicyViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicTargetStatus {
    Continue,
    Counterexample {
        kind: FuzzViolationKind,
        code: u16,
        public_witness_sha256: [u8; 32],
    },
    Unsupported {
        code: u16,
    },
    CheckerDisagreement {
        primary_code: u16,
        secondary_code: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicFuzzInput {
    pub step: u32,
    pub state: AdaptiveContextState,
    pub action: AdaptiveHostAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicTargetStep {
    pub observation: AdaptivePublicObservation,
    pub coverage: PublicCoverageSnapshot,
    pub logical_time_units: u32,
    pub status: PublicTargetStatus,
}

pub trait PublicFuzzTarget {
    fn execute(&mut self, input: PublicFuzzInput) -> PublicTargetStep;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveFuzzBudget {
    pub max_steps: u32,
    pub max_states: u32,
    pub max_logical_time_units: u64,
}

impl AdaptiveFuzzBudget {
    pub fn validate(self) -> Result<(), FuzzError> {
        if self.max_steps == 0
            || self.max_steps > HARD_MAX_STEPS
            || self.max_states == 0
            || self.max_states > HARD_MAX_STATES
            || self.max_logical_time_units == 0
            || self.max_logical_time_units > HARD_MAX_LOGICAL_TIME
        {
            return Err(FuzzError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveFuzzConfig {
    pub seed: u64,
    pub context_bounds: AdaptiveContextBounds,
    pub corpus_bounds: CorpusBounds,
    pub budget: AdaptiveFuzzBudget,
}

impl AdaptiveFuzzConfig {
    pub fn validate(self) -> Result<(), FuzzError> {
        self.context_bounds
            .validate()
            .map_err(|_| FuzzError::InvalidConfig)?;
        self.corpus_bounds
            .validate()
            .map_err(|_| FuzzError::InvalidConfig)?;
        self.budget.validate()?;
        if self.budget.max_steps > self.context_bounds.max_steps
            || self.budget.max_steps > self.corpus_bounds.max_actions_per_entry
        {
            return Err(FuzzError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FuzzInconclusiveReason {
    StepBound,
    StateBound,
    TimeBudget,
    Unsupported {
        code: u16,
    },
    CheckerDisagreement {
        primary_code: u16,
        secondary_code: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzCounterexample {
    pub step_index: u32,
    pub kind: FuzzViolationKind,
    pub code: u16,
    pub action: AdaptiveHostAction,
    pub public_witness_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FuzzVerdict {
    Counterexample { counterexample: FuzzCounterexample },
    Exhausted,
    Inconclusive { reason: FuzzInconclusiveReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzStep {
    pub index: u32,
    pub action_class: AdaptiveActionClass,
    pub action: AdaptiveHostAction,
    pub selector_word: u64,
    pub parameter_word: u64,
    pub action_program_sha256: [u8; 32],
    pub before_state_sha256: [u8; 32],
    pub after_state_sha256: [u8; 32],
    pub public_observation_sha256: [u8; 32],
    pub coverage_feedback_sha256: [u8; 32],
    pub corpus_sha256: [u8; 32],
    pub logical_time_total: u64,
    pub target_status: PublicTargetStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveFuzzReport {
    pub schema: String,
    pub seed: u64,
    pub context_bounds: AdaptiveContextBounds,
    pub corpus_bounds: CorpusBounds,
    pub budget: AdaptiveFuzzBudget,
    pub verdict: FuzzVerdict,
    pub steps: Vec<FuzzStep>,
    pub final_corpus_sha256: [u8; 32],
    pub public_randomness_sha256: [u8; 32],
    pub evidence_origin: String,
    pub hardware_status: String,
    pub artifact_sha256: [u8; 32],
}

impl AdaptiveFuzzReport {
    fn build(
        config: AdaptiveFuzzConfig,
        verdict: FuzzVerdict,
        steps: Vec<FuzzStep>,
        final_corpus_sha256: [u8; 32],
    ) -> Result<Self, FuzzError> {
        let mut report = Self {
            schema: ADAPTIVE_FUZZ_REPORT_SCHEMA.to_owned(),
            seed: config.seed,
            context_bounds: config.context_bounds,
            corpus_bounds: config.corpus_bounds,
            budget: config.budget,
            verdict,
            public_randomness_sha256: randomness_digest(config.seed, &steps),
            steps,
            final_corpus_sha256,
            evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            hardware_status: "NOT_VERIFIED".to_owned(),
            artifact_sha256: [0; 32],
        };
        report.artifact_sha256 = report.recomputed_sha256()?;
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), FuzzError> {
        let config = AdaptiveFuzzConfig {
            seed: self.seed,
            context_bounds: self.context_bounds,
            corpus_bounds: self.corpus_bounds,
            budget: self.budget,
        };
        config.validate()?;
        if self.schema != ADAPTIVE_FUZZ_REPORT_SCHEMA
            || self.evidence_origin != "INJECTED_TEST_FIXTURE"
            || self.hardware_status != "NOT_VERIFIED"
            || self.final_corpus_sha256 == [0; 32]
            || self.steps.len() > self.budget.max_steps as usize
        {
            return Err(FuzzError::ArtifactMismatch);
        }
        let mut classes = BTreeSet::new();
        let mut previous_time = 0;
        for (index, step) in self.steps.iter().enumerate() {
            if step.index != index as u32
                || step.action_class != AdaptiveActionClass::of(step.action)
                || !classes.insert(step.action_class)
                || step.action_program_sha256 == [0; 32]
                || step.before_state_sha256 == [0; 32]
                || step.after_state_sha256 == [0; 32]
                || step.public_observation_sha256 == [0; 32]
                || step.coverage_feedback_sha256 == [0; 32]
                || step.corpus_sha256 == [0; 32]
                || step.logical_time_total <= previous_time
                || step.logical_time_total > self.budget.max_logical_time_units
            {
                return Err(FuzzError::ArtifactMismatch);
            }
            previous_time = step.logical_time_total;
        }
        if self
            .steps
            .last()
            .is_some_and(|step| step.corpus_sha256 != self.final_corpus_sha256)
            || self.public_randomness_sha256 != randomness_digest(self.seed, &self.steps)
        {
            return Err(FuzzError::ArtifactMismatch);
        }
        match self.verdict {
            FuzzVerdict::Counterexample { counterexample } => {
                let Some(step) = self.steps.get(counterexample.step_index as usize) else {
                    return Err(FuzzError::ArtifactMismatch);
                };
                let expected = PublicTargetStatus::Counterexample {
                    kind: counterexample.kind,
                    code: counterexample.code,
                    public_witness_sha256: counterexample.public_witness_sha256,
                };
                if step.action != counterexample.action
                    || step.target_status != expected
                    || counterexample.code == 0
                    || counterexample.public_witness_sha256 == [0; 32]
                {
                    return Err(FuzzError::ArtifactMismatch);
                }
            }
            FuzzVerdict::Exhausted if classes.len() != AdaptiveActionClass::ALL.len() => {
                return Err(FuzzError::ArtifactMismatch);
            }
            FuzzVerdict::Exhausted | FuzzVerdict::Inconclusive { .. } => {}
        }
        if self.artifact_sha256 != self.recomputed_sha256()? {
            return Err(FuzzError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, FuzzError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| FuzzError::Json)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], FuzzError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| FuzzError::Json)?;
        Ok(domain_hash(REPORT_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FuzzError {
    #[error("adaptive fuzz configuration is invalid")]
    InvalidConfig,
    #[error("adaptive fuzz internal contract failed")]
    InternalContract,
    #[error("adaptive fuzz report failed full recomputation")]
    ArtifactMismatch,
    #[error("adaptive fuzz JSON serialization failed")]
    Json,
}

pub fn run_adaptive_fuzz<T: PublicFuzzTarget>(
    config: AdaptiveFuzzConfig,
    target: &mut T,
) -> Result<AdaptiveFuzzReport, FuzzError> {
    config.validate()?;
    let mut state = AdaptiveContextState::initial(config.context_bounds)
        .map_err(|_| FuzzError::InvalidConfig)?;
    let mut corpus = DeterministicCorpus::new(config.seed, config.corpus_bounds)
        .map_err(|_| FuzzError::InvalidConfig)?;
    let mut actions = Vec::new();
    let mut steps = Vec::new();
    let mut classes = BTreeSet::new();
    let mut states = BTreeSet::from([state.public_observation_sha256]);
    let mut logical_time = 0_u64;

    while classes.len() < AdaptiveActionClass::ALL.len() {
        if steps.len() >= config.budget.max_steps as usize {
            return finish(
                config,
                FuzzVerdict::Inconclusive {
                    reason: FuzzInconclusiveReason::StepBound,
                },
                steps,
                &corpus,
            );
        }
        let (class, selector_word, parameter_word, action) =
            select_action(config.seed, &state, &corpus, &classes);
        let target_step = target.execute(PublicFuzzInput {
            step: steps.len() as u32,
            state,
            action,
        });
        if target_step.logical_time_units == 0 {
            return inconclusive(
                config,
                FuzzInconclusiveReason::Unsupported { code: 1 },
                steps,
                &corpus,
            );
        }
        let Some(next_time) = logical_time.checked_add(u64::from(target_step.logical_time_units))
        else {
            return inconclusive(config, FuzzInconclusiveReason::TimeBudget, steps, &corpus);
        };
        if next_time > config.budget.max_logical_time_units {
            return inconclusive(config, FuzzInconclusiveReason::TimeBudget, steps, &corpus);
        }
        let transition = match apply_public_feedback(state, action, target_step.observation) {
            Ok(transition) => transition,
            Err(AdaptiveProgramError::StateBound) => {
                return inconclusive(config, FuzzInconclusiveReason::StateBound, steps, &corpus);
            }
            Err(_) => {
                return inconclusive(
                    config,
                    FuzzInconclusiveReason::Unsupported { code: 2 },
                    steps,
                    &corpus,
                );
            }
        };
        if !states.contains(&transition.after_sha256)
            && states.len() >= config.budget.max_states as usize
        {
            return inconclusive(config, FuzzInconclusiveReason::StateBound, steps, &corpus);
        }
        let feedback =
            match CoverageFeedback::from_public_transition(&transition, target_step.coverage) {
                Ok(feedback) => feedback,
                Err(_) => {
                    return inconclusive(
                        config,
                        FuzzInconclusiveReason::Unsupported { code: 3 },
                        steps,
                        &corpus,
                    );
                }
            };
        actions.push(action);
        let program =
            AdaptiveHostProgram::build(config.seed, config.context_bounds, actions.clone())
                .map_err(|_| FuzzError::InternalContract)?;
        let entry = CorpusEntry::build(
            config.seed,
            program.artifact_sha256,
            actions.len() as u32,
            feedback.clone(),
        )
        .map_err(|_| FuzzError::InternalContract)?;
        if let Err(error) = corpus.insert(entry) {
            let reason = match error {
                CoverageError::ActionBound
                | CoverageError::CorpusEntryBound
                | CoverageError::CorpusCoverageBound => FuzzInconclusiveReason::StateBound,
                _ => FuzzInconclusiveReason::Unsupported { code: 4 },
            };
            return inconclusive(config, reason, steps, &corpus);
        }
        classes.insert(class);
        states.insert(transition.after_sha256);
        logical_time = next_time;
        let index = steps.len() as u32;
        steps.push(FuzzStep {
            index,
            action_class: class,
            action,
            selector_word,
            parameter_word,
            action_program_sha256: program.artifact_sha256,
            before_state_sha256: transition.before_sha256,
            after_state_sha256: transition.after_sha256,
            public_observation_sha256: target_step.observation.public_trace_sha256,
            coverage_feedback_sha256: feedback.feedback_sha256,
            corpus_sha256: corpus.artifact_sha256,
            logical_time_total: logical_time,
            target_status: target_step.status,
        });
        state = transition.after;

        match target_step.status {
            PublicTargetStatus::Continue => {}
            PublicTargetStatus::Counterexample {
                kind,
                code,
                public_witness_sha256,
            } if code != 0 && public_witness_sha256 != [0; 32] => {
                return finish(
                    config,
                    FuzzVerdict::Counterexample {
                        counterexample: FuzzCounterexample {
                            step_index: index,
                            kind,
                            code,
                            action,
                            public_witness_sha256,
                        },
                    },
                    steps,
                    &corpus,
                );
            }
            PublicTargetStatus::Counterexample { .. } => {
                return inconclusive(
                    config,
                    FuzzInconclusiveReason::Unsupported { code: 5 },
                    steps,
                    &corpus,
                );
            }
            PublicTargetStatus::Unsupported { code } => {
                return inconclusive(
                    config,
                    FuzzInconclusiveReason::Unsupported { code },
                    steps,
                    &corpus,
                );
            }
            PublicTargetStatus::CheckerDisagreement {
                primary_code,
                secondary_code,
            } => {
                return inconclusive(
                    config,
                    FuzzInconclusiveReason::CheckerDisagreement {
                        primary_code,
                        secondary_code,
                    },
                    steps,
                    &corpus,
                );
            }
        }
    }
    finish(config, FuzzVerdict::Exhausted, steps, &corpus)
}

fn inconclusive(
    config: AdaptiveFuzzConfig,
    reason: FuzzInconclusiveReason,
    steps: Vec<FuzzStep>,
    corpus: &DeterministicCorpus,
) -> Result<AdaptiveFuzzReport, FuzzError> {
    finish(config, FuzzVerdict::Inconclusive { reason }, steps, corpus)
}

fn finish(
    config: AdaptiveFuzzConfig,
    verdict: FuzzVerdict,
    steps: Vec<FuzzStep>,
    corpus: &DeterministicCorpus,
) -> Result<AdaptiveFuzzReport, FuzzError> {
    AdaptiveFuzzReport::build(config, verdict, steps, corpus.artifact_sha256)
}

fn select_action(
    seed: u64,
    state: &AdaptiveContextState,
    corpus: &DeterministicCorpus,
    classes: &BTreeSet<AdaptiveActionClass>,
) -> (AdaptiveActionClass, u64, u64, AdaptiveHostAction) {
    let mut selected = None;
    for class in AdaptiveActionClass::ALL {
        if classes.contains(&class) {
            continue;
        }
        let word = adaptive_word(SELECTOR_DOMAIN, seed, state, corpus, class);
        if selected.is_none_or(|(best_class, best_word)| {
            word > best_word || (word == best_word && class < best_class)
        }) {
            selected = Some((class, word));
        }
    }
    let (class, selector_word) = selected.expect("an untried action class exists");
    let parameter_word = adaptive_word(PARAMETER_DOMAIN, seed, state, corpus, class);
    let action = materialize_action(class, parameter_word, state);
    (class, selector_word, parameter_word, action)
}

fn materialize_action(
    class: AdaptiveActionClass,
    word: u64,
    state: &AdaptiveContextState,
) -> AdaptiveHostAction {
    match class {
        AdaptiveActionClass::Tick => AdaptiveHostAction::Tick {
            public_slot: state.last_public_slot.saturating_add(1),
        },
        AdaptiveActionClass::Reset => AdaptiveHostAction::Reset {
            epoch: (word as u32).max(1),
        },
        AdaptiveActionClass::Handoff => AdaptiveHostAction::Handoff {
            service_alias: (word % u64::from(state.bounds.max_service_alias)) as u32,
        },
        AdaptiveActionClass::Malformed => AdaptiveHostAction::Malformed {
            payload_tag: word as u32,
        },
        AdaptiveActionClass::Repeat => AdaptiveHostAction::Repeat {
            count: (word % u64::from(state.bounds.max_repeat) + 1) as u8,
        },
        AdaptiveActionClass::StaleSlot => AdaptiveHostAction::StaleSlot {
            delta: (word % u64::from(u16::MAX) + 1) as u16,
        },
        AdaptiveActionClass::FutureSlot => AdaptiveHostAction::FutureSlot {
            delta: (word % u64::from(u16::MAX) + 1) as u16,
        },
        AdaptiveActionClass::Fault => AdaptiveHostAction::Fault {
            code: (word % u64::from(u8::MAX) + 1) as u8,
        },
        AdaptiveActionClass::Reconnect => AdaptiveHostAction::Reconnect {
            service_alias: (word % u64::from(state.bounds.max_service_alias)) as u32,
        },
        AdaptiveActionClass::ServiceSwitch => {
            let from = state.service_alias;
            let width = state.bounds.max_service_alias - 1;
            let offset = (word % u64::from(width) + 1) as u32;
            AdaptiveHostAction::ServiceSwitch {
                from,
                to: ((u64::from(from) + u64::from(offset))
                    % u64::from(state.bounds.max_service_alias)) as u32,
            }
        }
    }
}

fn adaptive_word(
    domain: &[u8],
    seed: u64,
    state: &AdaptiveContextState,
    corpus: &DeterministicCorpus,
    class: AdaptiveActionClass,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(seed.to_be_bytes());
    hasher.update(state.step.to_be_bytes());
    hasher.update(state.last_public_slot.to_be_bytes());
    hasher.update(state.service_alias.to_be_bytes());
    hasher.update([u8::from(state.connected)]);
    hasher.update(state.public_observation_sha256);
    hasher.update(corpus.artifact_sha256);
    hasher.update([class.code()]);
    let digest: [u8; 32] = hasher.finalize().into();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    )
}

fn randomness_digest(seed: u64, steps: &[FuzzStep]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RANDOMNESS_DOMAIN);
    hasher.update(seed.to_be_bytes());
    for step in steps {
        hasher.update(step.index.to_be_bytes());
        hasher.update([step.action_class.code()]);
        hasher.update(step.selector_word.to_be_bytes());
        hasher.update(step.parameter_word.to_be_bytes());
    }
    hasher.finalize().into()
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
