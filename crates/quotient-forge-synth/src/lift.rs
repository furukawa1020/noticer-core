//! Validated translation from quotient-indexed candidates to source-state policies.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::preservation::{PreservationStatus, QuotientPreservationArtifact};
use crate::quotient::QuotientPartition;

pub const QUOTIENT_LIFT_SCHEMA_V1: &str = "noticer.quotient_forge.quotient_lift.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LiftMapEntry {
    pub source_index: u32,
    pub class_id: u32,
}

impl LiftMapEntry {
    pub const fn new(source_index: u32, class_id: u32) -> Self {
        Self {
            source_index,
            class_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiftMapping {
    problem_sha256: String,
    quotient_artifact_sha256: String,
    entries: Vec<LiftMapEntry>,
    mapping_commitment_sha256: String,
}

impl LiftMapping {
    pub fn new(
        problem_sha256: impl Into<String>,
        quotient_artifact_sha256: impl Into<String>,
        mut entries: Vec<LiftMapEntry>,
    ) -> Result<Self, QuotientLiftError> {
        let problem_sha256 = problem_sha256.into();
        let quotient_artifact_sha256 = quotient_artifact_sha256.into();
        require_sha256("problem_sha256", &problem_sha256)?;
        require_sha256("quotient_artifact_sha256", &quotient_artifact_sha256)?;
        if entries.is_empty() {
            return Err(QuotientLiftError::EmptyMapping);
        }
        entries.sort();
        if entries
            .windows(2)
            .any(|pair| pair[0].source_index == pair[1].source_index)
        {
            return Err(QuotientLiftError::DuplicateMappingSource);
        }
        let mapping_commitment_sha256 = mapping_commitment(&entries)?;
        Ok(Self {
            problem_sha256,
            quotient_artifact_sha256,
            entries,
            mapping_commitment_sha256,
        })
    }

    pub fn from_partition(partition: &QuotientPartition) -> Result<Self, QuotientLiftError> {
        Self::new(
            partition.artifact.problem_sha256.clone(),
            partition.artifact.artifact_sha256.clone(),
            partition
                .source_class_pairs()
                .map(|(source_index, class_id)| LiftMapEntry::new(source_index, class_id))
                .collect(),
        )
    }

    pub fn entries(&self) -> &[LiftMapEntry] {
        &self.entries
    }

    pub fn mapping_commitment_sha256(&self) -> &str {
        &self.mapping_commitment_sha256
    }

    fn validate(
        &self,
        problem_sha256: &str,
        partition: &QuotientPartition,
    ) -> Result<(), QuotientLiftError> {
        if self.problem_sha256 != problem_sha256 {
            return Err(QuotientLiftError::StaleMappingProblem);
        }
        if self.quotient_artifact_sha256 != partition.artifact.artifact_sha256 {
            return Err(QuotientLiftError::StaleMappingQuotient);
        }
        if self.entries.len() != partition.mapped_state_count() {
            return Err(QuotientLiftError::MappingNotTotal);
        }
        let mut represented_classes = BTreeSet::new();
        for entry in &self.entries {
            let Some(expected_class) = partition.class_for_source_index(entry.source_index) else {
                return Err(QuotientLiftError::UnknownMappingSource);
            };
            if entry.class_id != expected_class {
                return Err(QuotientLiftError::IncorrectMappingClass);
            }
            represented_classes.insert(entry.class_id);
        }
        if represented_classes.len() != partition.artifact.classes.len() {
            return Err(QuotientLiftError::MappingNotSurjective);
        }
        if mapping_commitment(&self.entries)? != self.mapping_commitment_sha256 {
            return Err(QuotientLiftError::MappingCommitmentMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ReducedPolicyCell {
    pub control_state: u32,
    pub class_id: u32,
    pub symbol_id: u32,
    pub next_control_state: u32,
    pub output_sha256: String,
}

impl ReducedPolicyCell {
    pub fn new(
        control_state: u32,
        class_id: u32,
        symbol_id: u32,
        next_control_state: u32,
        output_sha256: impl Into<String>,
    ) -> Result<Self, QuotientLiftError> {
        let cell = Self {
            control_state,
            class_id,
            symbol_id,
            next_control_state,
            output_sha256: output_sha256.into(),
        };
        require_sha256("output_sha256", &cell.output_sha256)?;
        Ok(cell)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReducedCandidate {
    pub control_state_count: u32,
    pub quotient_class_count: u32,
    pub symbol_count: u32,
    pub cells: Vec<ReducedPolicyCell>,
    pub candidate_sha256: String,
}

impl ReducedCandidate {
    pub fn new(
        control_state_count: u32,
        quotient_class_count: u32,
        symbol_count: u32,
        mut cells: Vec<ReducedPolicyCell>,
    ) -> Result<Self, QuotientLiftError> {
        cells.sort();
        let mut candidate = Self {
            control_state_count,
            quotient_class_count,
            symbol_count,
            cells,
            candidate_sha256: String::new(),
        };
        candidate.validate_shape()?;
        candidate.candidate_sha256 = candidate.digest()?;
        Ok(candidate)
    }

    pub fn validate(&self) -> Result<(), QuotientLiftError> {
        self.validate_shape()?;
        require_sha256("candidate_sha256", &self.candidate_sha256)?;
        if self.digest()? != self.candidate_sha256 {
            return Err(QuotientLiftError::ReducedCandidateDigestMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), QuotientLiftError> {
        if self.control_state_count == 0 || self.quotient_class_count == 0 || self.symbol_count == 0
        {
            return Err(QuotientLiftError::InvalidReducedDimensions);
        }
        let expected = u64::from(self.control_state_count)
            .checked_mul(u64::from(self.quotient_class_count))
            .and_then(|value| value.checked_mul(u64::from(self.symbol_count)))
            .ok_or(QuotientLiftError::ModelTooLarge)?;
        if u64::try_from(self.cells.len()).map_err(|_| QuotientLiftError::ModelTooLarge)?
            != expected
        {
            return Err(QuotientLiftError::ReducedCandidateNotTotal);
        }
        let mut expected_keys = (0..self.control_state_count).flat_map(|control_state| {
            (0..self.quotient_class_count).flat_map(move |class_id| {
                (0..self.symbol_count).map(move |symbol_id| (control_state, class_id, symbol_id))
            })
        });
        for cell in &self.cells {
            require_sha256("output_sha256", &cell.output_sha256)?;
            if cell.next_control_state >= self.control_state_count
                || Some((cell.control_state, cell.class_id, cell.symbol_id)) != expected_keys.next()
            {
                return Err(QuotientLiftError::ReducedCandidateNotCanonical);
            }
        }
        if expected_keys.next().is_some() {
            return Err(QuotientLiftError::ReducedCandidateNotTotal);
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, QuotientLiftError> {
        let mut payload = self.clone();
        payload.candidate_sha256.clear();
        canonical_json_sha256(&payload)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LiftedPolicyCell {
    pub control_state: u32,
    pub source_index: u32,
    pub symbol_id: u32,
    pub next_control_state: u32,
    pub output_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiftedCandidate {
    pub control_state_count: u32,
    pub source_state_count: u32,
    pub symbol_count: u32,
    pub cells: Vec<LiftedPolicyCell>,
    pub candidate_sha256: String,
}

#[derive(Serialize)]
struct NormalizedLiftedCandidate<'a> {
    control_state_count: u32,
    source_state_count: u32,
    symbol_count: u32,
    cells: Vec<NormalizedLiftedCell<'a>>,
}

#[derive(Serialize)]
struct NormalizedLiftedCell<'a> {
    control_state: u32,
    source_ordinal: u32,
    symbol_id: u32,
    next_control_state: u32,
    output_sha256: &'a str,
}

impl LiftedCandidate {
    fn digest(&self) -> Result<String, QuotientLiftError> {
        let source_ordinals = self
            .cells
            .iter()
            .map(|cell| cell.source_index)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(ordinal, source_index)| {
                u32::try_from(ordinal)
                    .map(|ordinal| (source_index, ordinal))
                    .map_err(|_| QuotientLiftError::ModelTooLarge)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let cells = self
            .cells
            .iter()
            .map(|cell| NormalizedLiftedCell {
                control_state: cell.control_state,
                source_ordinal: source_ordinals[&cell.source_index],
                symbol_id: cell.symbol_id,
                next_control_state: cell.next_control_state,
                output_sha256: &cell.output_sha256,
            })
            .collect();
        canonical_json_sha256(&NormalizedLiftedCandidate {
            control_state_count: self.control_state_count,
            source_state_count: self.source_state_count,
            symbol_count: self.symbol_count,
            cells,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiftCheckerDecision {
    Valid,
    Invalid,
    Inconclusive,
}

pub trait LiftedCandidateChecker {
    fn check(
        &self,
        partition: &QuotientPartition,
        mapping: &LiftMapping,
        reduced_candidate: &ReducedCandidate,
        lifted_candidate: &LiftedCandidate,
    ) -> LiftCheckerDecision;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotientLiftArtifact {
    pub schema_version: String,
    pub problem_sha256: String,
    pub quotient_artifact_sha256: String,
    pub preservation_artifact_sha256: String,
    pub mapping_commitment_sha256: String,
    pub reduced_candidate_sha256: String,
    pub lifted_candidate_sha256: String,
    pub source_state_count: u32,
    pub quotient_class_count: u32,
    pub reduced_cell_count: u64,
    pub lifted_cell_count: u64,
    pub mapping_total: bool,
    pub mapping_unique: bool,
    pub mapping_surjective: bool,
    pub checker_calls: u32,
    pub checker_decision: LiftCheckerDecision,
    pub accepted: bool,
    pub source_indices_included: bool,
    pub artifact_sha256: String,
}

impl QuotientLiftArtifact {
    pub fn validate(&self) -> Result<(), QuotientLiftError> {
        if self.schema_version != QUOTIENT_LIFT_SCHEMA_V1 {
            return Err(QuotientLiftError::SchemaVersion);
        }
        for (field, value) in [
            ("problem_sha256", &self.problem_sha256),
            ("quotient_artifact_sha256", &self.quotient_artifact_sha256),
            (
                "preservation_artifact_sha256",
                &self.preservation_artifact_sha256,
            ),
            ("mapping_commitment_sha256", &self.mapping_commitment_sha256),
            ("reduced_candidate_sha256", &self.reduced_candidate_sha256),
            ("lifted_candidate_sha256", &self.lifted_candidate_sha256),
            ("artifact_sha256", &self.artifact_sha256),
        ] {
            require_sha256(field, value)?;
        }
        if self.source_state_count == 0
            || self.quotient_class_count == 0
            || self.reduced_cell_count == 0
            || self.lifted_cell_count == 0
            || self.lifted_cell_count < self.reduced_cell_count
            || !self.mapping_total
            || !self.mapping_unique
            || !self.mapping_surjective
            || self.checker_calls != 1
            || self.accepted != (self.checker_decision == LiftCheckerDecision::Valid)
            || self.source_indices_included
        {
            return Err(QuotientLiftError::InvalidArtifact);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(QuotientLiftError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientLiftResult {
    pub lifted_candidate: LiftedCandidate,
    pub artifact: QuotientLiftArtifact,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum QuotientLiftError {
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("lift mapping must contain at least one entry")]
    EmptyMapping,
    #[error("lift mapping contains a duplicate source index")]
    DuplicateMappingSource,
    #[error("lift mapping belongs to a different problem")]
    StaleMappingProblem,
    #[error("lift mapping belongs to a different quotient artifact")]
    StaleMappingQuotient,
    #[error("lift mapping does not cover every source state")]
    MappingNotTotal,
    #[error("lift mapping references an unknown source state")]
    UnknownMappingSource,
    #[error("lift mapping assigns a source state to the wrong class")]
    IncorrectMappingClass,
    #[error("lift mapping does not cover every quotient class")]
    MappingNotSurjective,
    #[error("lift mapping commitment is inconsistent")]
    MappingCommitmentMismatch,
    #[error("quotient artifact is invalid or stale")]
    InvalidQuotient,
    #[error("preservation artifact is invalid or stale")]
    InvalidPreservation,
    #[error("quotient preservation did not pass")]
    PreservationNotPassed,
    #[error("reduced candidate dimensions must be non-zero")]
    InvalidReducedDimensions,
    #[error("reduced candidate does not define every input exactly once")]
    ReducedCandidateNotTotal,
    #[error("reduced candidate table is not canonical")]
    ReducedCandidateNotCanonical,
    #[error("reduced candidate class count does not match the quotient")]
    ReducedCandidateClassMismatch,
    #[error("reduced candidate digest is inconsistent")]
    ReducedCandidateDigestMismatch,
    #[error("model exceeds representable artifact bounds")]
    ModelTooLarge,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("quotient lift artifact is inconsistent")]
    InvalidArtifact,
    #[error("{0} does not match its canonical payload")]
    DigestMismatch(&'static str),
    #[error("canonical artifact serialization failed")]
    Serialization,
}

pub fn lift_reduced_candidate<C: LiftedCandidateChecker>(
    problem_sha256: impl Into<String>,
    partition: &QuotientPartition,
    preservation: &QuotientPreservationArtifact,
    mapping: &LiftMapping,
    reduced_candidate: &ReducedCandidate,
    checker: &C,
) -> Result<QuotientLiftResult, QuotientLiftError> {
    let problem_sha256 = problem_sha256.into();
    require_sha256("problem_sha256", &problem_sha256)?;
    partition
        .artifact
        .validate()
        .map_err(|_| QuotientLiftError::InvalidQuotient)?;
    if partition.artifact.problem_sha256 != problem_sha256 {
        return Err(QuotientLiftError::InvalidQuotient);
    }
    preservation
        .validate()
        .map_err(|_| QuotientLiftError::InvalidPreservation)?;
    if preservation.problem_sha256 != problem_sha256
        || preservation.quotient_artifact_sha256 != partition.artifact.artifact_sha256
    {
        return Err(QuotientLiftError::InvalidPreservation);
    }
    if preservation.overall_status != PreservationStatus::Pass || !preservation.reduction_enabled {
        return Err(QuotientLiftError::PreservationNotPassed);
    }
    mapping.validate(&problem_sha256, partition)?;
    reduced_candidate.validate()?;
    let class_count = u32::try_from(partition.artifact.classes.len())
        .map_err(|_| QuotientLiftError::ModelTooLarge)?;
    if reduced_candidate.quotient_class_count != class_count {
        return Err(QuotientLiftError::ReducedCandidateClassMismatch);
    }

    let reduced_by_key = reduced_candidate
        .cells
        .iter()
        .map(|cell| ((cell.control_state, cell.class_id, cell.symbol_id), cell))
        .collect::<BTreeMap<_, _>>();
    let mut cells = Vec::new();
    for control_state in 0..reduced_candidate.control_state_count {
        for entry in &mapping.entries {
            for symbol_id in 0..reduced_candidate.symbol_count {
                let reduced = reduced_by_key[&(control_state, entry.class_id, symbol_id)];
                cells.push(LiftedPolicyCell {
                    control_state,
                    source_index: entry.source_index,
                    symbol_id,
                    next_control_state: reduced.next_control_state,
                    output_sha256: reduced.output_sha256.clone(),
                });
            }
        }
    }
    let source_state_count =
        u32::try_from(mapping.entries.len()).map_err(|_| QuotientLiftError::ModelTooLarge)?;
    let mut lifted_candidate = LiftedCandidate {
        control_state_count: reduced_candidate.control_state_count,
        source_state_count,
        symbol_count: reduced_candidate.symbol_count,
        cells,
        candidate_sha256: String::new(),
    };
    lifted_candidate.candidate_sha256 = lifted_candidate.digest()?;

    let checker_decision = checker.check(partition, mapping, reduced_candidate, &lifted_candidate);
    let reduced_cell_count = u64::try_from(reduced_candidate.cells.len())
        .map_err(|_| QuotientLiftError::ModelTooLarge)?;
    let lifted_cell_count = u64::try_from(lifted_candidate.cells.len())
        .map_err(|_| QuotientLiftError::ModelTooLarge)?;
    let mut artifact = QuotientLiftArtifact {
        schema_version: QUOTIENT_LIFT_SCHEMA_V1.to_owned(),
        problem_sha256,
        quotient_artifact_sha256: partition.artifact.artifact_sha256.clone(),
        preservation_artifact_sha256: preservation.artifact_sha256.clone(),
        mapping_commitment_sha256: mapping.mapping_commitment_sha256.clone(),
        reduced_candidate_sha256: reduced_candidate.candidate_sha256.clone(),
        lifted_candidate_sha256: lifted_candidate.candidate_sha256.clone(),
        source_state_count,
        quotient_class_count: class_count,
        reduced_cell_count,
        lifted_cell_count,
        mapping_total: true,
        mapping_unique: true,
        mapping_surjective: true,
        checker_calls: 1,
        checker_decision,
        accepted: checker_decision == LiftCheckerDecision::Valid,
        source_indices_included: false,
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate()?;
    Ok(QuotientLiftResult {
        lifted_candidate,
        artifact,
    })
}

fn mapping_commitment(entries: &[LiftMapEntry]) -> Result<String, QuotientLiftError> {
    canonical_json_sha256(
        &entries
            .iter()
            .map(|entry| entry.class_id)
            .collect::<Vec<_>>(),
    )
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), QuotientLiftError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(QuotientLiftError::InvalidSha256(field))
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, QuotientLiftError> {
    let bytes = serde_json::to_vec(value).map_err(|_| QuotientLiftError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
