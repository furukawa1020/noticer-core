//! Independent preservation obligations for action-semantics quotients.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::quotient::QuotientPartition;

pub const QUOTIENT_PRESERVATION_SCHEMA_V1: &str = "noticer.quotient_forge.quotient_preservation.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObserverEvent {
    pub channel_sha256: String,
    pub value_sha256: String,
}

impl ObserverEvent {
    pub fn new(
        channel_sha256: impl Into<String>,
        value_sha256: impl Into<String>,
    ) -> Result<Self, PreservationError> {
        let event = Self {
            channel_sha256: channel_sha256.into(),
            value_sha256: value_sha256.into(),
        };
        event.validate()?;
        Ok(event)
    }

    fn validate(&self) -> Result<(), PreservationError> {
        require_sha256("channel_sha256", &self.channel_sha256)?;
        require_sha256("value_sha256", &self.value_sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FaultTransition {
    pub trigger_sha256: String,
    pub target_source_index: u32,
    pub observable_effect_sha256: String,
}

impl FaultTransition {
    pub fn new(
        trigger_sha256: impl Into<String>,
        target_source_index: u32,
        observable_effect_sha256: impl Into<String>,
    ) -> Result<Self, PreservationError> {
        let transition = Self {
            trigger_sha256: trigger_sha256.into(),
            target_source_index,
            observable_effect_sha256: observable_effect_sha256.into(),
        };
        transition.validate()?;
        Ok(transition)
    }

    fn validate(&self) -> Result<(), PreservationError> {
        require_sha256("trigger_sha256", &self.trigger_sha256)?;
        require_sha256("observable_effect_sha256", &self.observable_effect_sha256)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreservationState {
    source_index: u32,
    observer_trace: Vec<ObserverEvent>,
    utility_obligation_sha256: Vec<String>,
    fault_transitions: Vec<FaultTransition>,
}

impl PreservationState {
    pub fn new(
        source_index: u32,
        observer_trace: Vec<ObserverEvent>,
        mut utility_obligation_sha256: Vec<String>,
        mut fault_transitions: Vec<FaultTransition>,
    ) -> Result<Self, PreservationError> {
        if observer_trace.is_empty() {
            return Err(PreservationError::EmptyObserverTrace);
        }
        for event in &observer_trace {
            event.validate()?;
        }
        for digest in &utility_obligation_sha256 {
            require_sha256("utility_obligation_sha256", digest)?;
        }
        utility_obligation_sha256.sort();
        if utility_obligation_sha256
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(PreservationError::DuplicateUtilityObligation);
        }
        for transition in &fault_transitions {
            transition.validate()?;
        }
        fault_transitions.sort();
        if fault_transitions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PreservationError::DuplicateFaultTransition);
        }
        Ok(Self {
            source_index,
            observer_trace,
            utility_obligation_sha256,
            fault_transitions,
        })
    }

    pub const fn source_index(&self) -> u32 {
        self.source_index
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationObligation {
    ObserverTrace,
    Utility,
    Fault,
}

impl PreservationObligation {
    pub const ALL: [Self; 3] = [Self::ObserverTrace, Self::Utility, Self::Fault];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationStatus {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationInconclusiveReason {
    PairLimit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreservationWitness {
    pub obligation: PreservationObligation,
    pub class_id: u32,
    pub left_member_ordinal: u32,
    pub right_member_ordinal: u32,
    pub left_signature_sha256: String,
    pub right_signature_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObligationResult {
    pub obligation: PreservationObligation,
    pub status: PreservationStatus,
    pub witness: Option<PreservationWitness>,
    pub inconclusive_reason: Option<PreservationInconclusiveReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreservationLimits {
    pub max_state_pairs: u64,
}

impl PreservationLimits {
    fn validate(&self) -> Result<(), PreservationError> {
        if self.max_state_pairs == 0 {
            return Err(PreservationError::InvalidPairLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotientPreservationArtifact {
    pub schema_version: String,
    pub problem_sha256: String,
    pub quotient_artifact_sha256: String,
    pub checked_state_count: u32,
    pub required_state_pairs: u64,
    pub checked_state_pairs: u64,
    pub obligation_results: Vec<ObligationResult>,
    pub overall_status: PreservationStatus,
    pub reduction_enabled: bool,
    pub source_indices_included: bool,
    pub artifact_sha256: String,
}

impl QuotientPreservationArtifact {
    pub fn validate(&self) -> Result<(), PreservationError> {
        if self.schema_version != QUOTIENT_PRESERVATION_SCHEMA_V1 {
            return Err(PreservationError::SchemaVersion);
        }
        require_sha256("problem_sha256", &self.problem_sha256)?;
        require_sha256("quotient_artifact_sha256", &self.quotient_artifact_sha256)?;
        require_sha256("artifact_sha256", &self.artifact_sha256)?;
        if self.checked_state_count == 0
            || self.checked_state_pairs > self.required_state_pairs
            || self.source_indices_included
            || self.obligation_results.len() != PreservationObligation::ALL.len()
            || self
                .obligation_results
                .iter()
                .zip(PreservationObligation::ALL)
                .any(|(result, expected)| result.obligation != expected)
        {
            return Err(PreservationError::InvalidArtifact);
        }
        for result in &self.obligation_results {
            match result.status {
                PreservationStatus::Pass => {
                    if result.witness.is_some() || result.inconclusive_reason.is_some() {
                        return Err(PreservationError::InvalidArtifact);
                    }
                }
                PreservationStatus::Fail => {
                    if result.witness.is_none() || result.inconclusive_reason.is_some() {
                        return Err(PreservationError::InvalidArtifact);
                    }
                }
                PreservationStatus::Inconclusive => {
                    if result.witness.is_some() || result.inconclusive_reason.is_none() {
                        return Err(PreservationError::InvalidArtifact);
                    }
                }
            }
            if let Some(witness) = &result.witness {
                if witness.obligation != result.obligation
                    || witness.left_member_ordinal >= witness.right_member_ordinal
                {
                    return Err(PreservationError::InvalidArtifact);
                }
                require_sha256("left_signature_sha256", &witness.left_signature_sha256)?;
                require_sha256("right_signature_sha256", &witness.right_signature_sha256)?;
            }
        }
        let expected_overall = if self
            .obligation_results
            .iter()
            .any(|result| result.status == PreservationStatus::Fail)
        {
            PreservationStatus::Fail
        } else if self
            .obligation_results
            .iter()
            .any(|result| result.status == PreservationStatus::Inconclusive)
        {
            PreservationStatus::Inconclusive
        } else {
            PreservationStatus::Pass
        };
        if self.overall_status != expected_overall
            || self.reduction_enabled != (expected_overall == PreservationStatus::Pass)
            || expected_overall == PreservationStatus::Pass
                && self.checked_state_pairs != self.required_state_pairs
        {
            return Err(PreservationError::InvalidArtifact);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(PreservationError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreservationCheck {
    pub artifact: QuotientPreservationArtifact,
    witness_source_pairs: BTreeMap<PreservationObligation, (u32, u32)>,
}

impl PreservationCheck {
    pub fn source_pair_for(&self, obligation: PreservationObligation) -> Option<(u32, u32)> {
        self.witness_source_pairs.get(&obligation).copied()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PreservationError {
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("complete observer trace must be non-empty")]
    EmptyObserverTrace,
    #[error("utility obligation is duplicated")]
    DuplicateUtilityObligation,
    #[error("fault transition is duplicated")]
    DuplicateFaultTransition,
    #[error("max_state_pairs must be greater than zero")]
    InvalidPairLimit,
    #[error("preservation state index is duplicated")]
    DuplicateSourceIndex,
    #[error("preservation state is absent from the quotient")]
    UnknownSourceIndex,
    #[error("preservation data does not cover every quotient state")]
    MissingStateData,
    #[error("fault transition target is absent from the quotient")]
    UnknownFaultTarget,
    #[error("state count exceeds artifact bounds")]
    ModelTooLarge,
    #[error("quotient artifact is invalid")]
    InvalidQuotient,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("preservation artifact is inconsistent")]
    InvalidArtifact,
    #[error("{0} does not match its canonical payload")]
    DigestMismatch(&'static str),
    #[error("canonical artifact serialization failed")]
    Serialization,
}

pub fn check_quotient_preservation(
    problem_sha256: impl Into<String>,
    partition: &QuotientPartition,
    states: &[PreservationState],
    limits: &PreservationLimits,
) -> Result<PreservationCheck, PreservationError> {
    let problem_sha256 = problem_sha256.into();
    require_sha256("problem_sha256", &problem_sha256)?;
    limits.validate()?;
    partition
        .artifact
        .validate()
        .map_err(|_| PreservationError::InvalidQuotient)?;
    if partition.artifact.problem_sha256 != problem_sha256 {
        return Err(PreservationError::InvalidQuotient);
    }
    let mut seen = BTreeSet::new();
    let mut by_class = BTreeMap::<u32, Vec<&PreservationState>>::new();
    for state in states {
        if !seen.insert(state.source_index) {
            return Err(PreservationError::DuplicateSourceIndex);
        }
        let class_id = partition
            .class_for_source_index(state.source_index)
            .ok_or(PreservationError::UnknownSourceIndex)?;
        by_class.entry(class_id).or_default().push(state);
    }
    if states.len() != partition.mapped_state_count() {
        return Err(PreservationError::MissingStateData);
    }
    for members in by_class.values_mut() {
        members.sort_by_key(|state| state.source_index);
    }
    let required_state_pairs = by_class.values().try_fold(0_u64, |total, members| {
        let count = u64::try_from(members.len()).map_err(|_| PreservationError::ModelTooLarge)?;
        total
            .checked_add(count.saturating_sub(1).saturating_mul(count) / 2)
            .ok_or(PreservationError::ModelTooLarge)
    })?;
    let checked_state_count =
        u32::try_from(states.len()).map_err(|_| PreservationError::ModelTooLarge)?;
    if required_state_pairs > limits.max_state_pairs {
        return finish_check(
            problem_sha256,
            partition,
            checked_state_count,
            required_state_pairs,
            0,
            PreservationObligation::ALL
                .into_iter()
                .map(|obligation| ObligationResult {
                    obligation,
                    status: PreservationStatus::Inconclusive,
                    witness: None,
                    inconclusive_reason: Some(PreservationInconclusiveReason::PairLimit),
                })
                .collect(),
            BTreeMap::new(),
        );
    }

    let mut results = PreservationObligation::ALL.map(|obligation| ObligationResult {
        obligation,
        status: PreservationStatus::Pass,
        witness: None,
        inconclusive_reason: None,
    });
    let mut witness_source_pairs = BTreeMap::new();
    let mut checked_state_pairs = 0_u64;
    for (class_id, members) in &by_class {
        let signatures = members
            .iter()
            .map(|state| state_signatures(state, partition))
            .collect::<Result<Vec<_>, PreservationError>>()?;
        for left in 0..members.len() {
            for right in left + 1..members.len() {
                checked_state_pairs += 1;
                for (result, (left_signature, right_signature)) in results.iter_mut().zip([
                    (&signatures[left].observer, &signatures[right].observer),
                    (&signatures[left].utility, &signatures[right].utility),
                    (&signatures[left].fault, &signatures[right].fault),
                ]) {
                    if result.status == PreservationStatus::Pass
                        && left_signature != right_signature
                    {
                        result.status = PreservationStatus::Fail;
                        result.witness = Some(PreservationWitness {
                            obligation: result.obligation,
                            class_id: *class_id,
                            left_member_ordinal: left as u32,
                            right_member_ordinal: right as u32,
                            left_signature_sha256: left_signature.clone(),
                            right_signature_sha256: right_signature.clone(),
                        });
                        witness_source_pairs.insert(
                            result.obligation,
                            (members[left].source_index, members[right].source_index),
                        );
                    }
                }
            }
        }
    }
    finish_check(
        problem_sha256,
        partition,
        checked_state_count,
        required_state_pairs,
        checked_state_pairs,
        results.into_iter().collect(),
        witness_source_pairs,
    )
}

struct StateSignatures {
    observer: String,
    utility: String,
    fault: String,
}

#[derive(Serialize)]
struct NormalizedFaultTransition<'a> {
    trigger_sha256: &'a str,
    target_class_id: u32,
    observable_effect_sha256: &'a str,
}

fn state_signatures(
    state: &PreservationState,
    partition: &QuotientPartition,
) -> Result<StateSignatures, PreservationError> {
    let observer = canonical_json_sha256(&state.observer_trace)?;
    let utility = canonical_json_sha256(&state.utility_obligation_sha256)?;
    let mut normalized_faults = state
        .fault_transitions
        .iter()
        .map(|transition| {
            let target_class_id = partition
                .class_for_source_index(transition.target_source_index)
                .ok_or(PreservationError::UnknownFaultTarget)?;
            Ok(NormalizedFaultTransition {
                trigger_sha256: &transition.trigger_sha256,
                target_class_id,
                observable_effect_sha256: &transition.observable_effect_sha256,
            })
        })
        .collect::<Result<Vec<_>, PreservationError>>()?;
    normalized_faults.sort_by_key(|transition| {
        (
            transition.trigger_sha256,
            transition.target_class_id,
            transition.observable_effect_sha256,
        )
    });
    let fault = canonical_json_sha256(&normalized_faults)?;
    Ok(StateSignatures {
        observer,
        utility,
        fault,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_check(
    problem_sha256: String,
    partition: &QuotientPartition,
    checked_state_count: u32,
    required_state_pairs: u64,
    checked_state_pairs: u64,
    obligation_results: Vec<ObligationResult>,
    witness_source_pairs: BTreeMap<PreservationObligation, (u32, u32)>,
) -> Result<PreservationCheck, PreservationError> {
    let overall_status = if obligation_results
        .iter()
        .any(|result| result.status == PreservationStatus::Fail)
    {
        PreservationStatus::Fail
    } else if obligation_results
        .iter()
        .any(|result| result.status == PreservationStatus::Inconclusive)
    {
        PreservationStatus::Inconclusive
    } else {
        PreservationStatus::Pass
    };
    let mut artifact = QuotientPreservationArtifact {
        schema_version: QUOTIENT_PRESERVATION_SCHEMA_V1.to_owned(),
        problem_sha256,
        quotient_artifact_sha256: partition.artifact.artifact_sha256.clone(),
        checked_state_count,
        required_state_pairs,
        checked_state_pairs,
        obligation_results,
        overall_status,
        reduction_enabled: overall_status == PreservationStatus::Pass,
        source_indices_included: false,
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate()?;
    Ok(PreservationCheck {
        artifact,
        witness_source_pairs,
    })
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), PreservationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(PreservationError::InvalidSha256(field))
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, PreservationError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PreservationError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
