use crate::AdaptiveStateTransition;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const COVERAGE_FEEDBACK_SCHEMA: &str = "quotient-seal.coverage-feedback.v1";
pub const COVERAGE_CORPUS_SCHEMA: &str = "quotient-seal.deterministic-corpus.v1";

const COVERAGE_POINT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_COVERAGE_POINT_V1";
const COVERAGE_FEEDBACK_DOMAIN: &[u8] = b"QUOTIENT_SEAL_COVERAGE_FEEDBACK_V1";
const CORPUS_ENTRY_DOMAIN: &[u8] = b"QUOTIENT_SEAL_CORPUS_ENTRY_V1";
const CORPUS_DOMAIN: &[u8] = b"QUOTIENT_SEAL_DETERMINISTIC_CORPUS_V1";
const MAX_FEEDBACK_RECORDS: usize = 4_096;
const HARD_MAX_ENTRIES: u32 = 4_096;
const HARD_MAX_COVERAGE_POINTS: u32 = 65_536;
const HARD_MAX_ACTIONS_PER_ENTRY: u32 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageKind {
    TargetBlock,
    ProductState,
    ObserverDivergence,
    ContextState,
    UtilityViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoveragePoint {
    TargetBlock {
        block_id: u32,
    },
    ProductState {
        source_state: u32,
        target_state: u32,
    },
    ObserverDivergence {
        observer_profile: u16,
        divergence_code: u16,
        public_trace_sha256: [u8; 32],
    },
    ContextState {
        step: u32,
        service_alias: u32,
        connected: bool,
        public_state_sha256: [u8; 32],
    },
    UtilityViolation {
        obligation_id: u32,
        violation_code: u16,
        public_slot: u64,
    },
}

impl CoveragePoint {
    #[must_use]
    pub const fn kind(&self) -> CoverageKind {
        match self {
            Self::TargetBlock { .. } => CoverageKind::TargetBlock,
            Self::ProductState { .. } => CoverageKind::ProductState,
            Self::ObserverDivergence { .. } => CoverageKind::ObserverDivergence,
            Self::ContextState { .. } => CoverageKind::ContextState,
            Self::UtilityViolation { .. } => CoverageKind::UtilityViolation,
        }
    }

    fn validate(&self) -> Result<(), CoverageError> {
        match self {
            Self::ObserverDivergence {
                divergence_code,
                public_trace_sha256,
                ..
            } if *divergence_code == 0 || *public_trace_sha256 == [0; 32] => {
                Err(CoverageError::InvalidPoint)
            }
            Self::ContextState {
                step,
                public_state_sha256,
                ..
            } if *step == 0 || *public_state_sha256 == [0; 32] => Err(CoverageError::InvalidPoint),
            Self::UtilityViolation { violation_code, .. } if *violation_code == 0 => {
                Err(CoverageError::InvalidPoint)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRecord {
    pub coverage_id: [u8; 32],
    pub point: CoveragePoint,
}

impl CoverageRecord {
    pub fn build(point: CoveragePoint) -> Result<Self, CoverageError> {
        point.validate()?;
        let encoded = serde_json::to_vec(&point).map_err(|_| CoverageError::Json)?;
        Ok(Self {
            coverage_id: domain_hash(COVERAGE_POINT_DOMAIN, &encoded),
            point,
        })
    }

    pub fn validate(&self) -> Result<(), CoverageError> {
        let expected = Self::build(self.point.clone())?;
        if self != &expected {
            return Err(CoverageError::CoverageDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicObserverDivergence {
    pub observer_profile: u16,
    pub divergence_code: u16,
    pub public_trace_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicUtilityViolation {
    pub obligation_id: u32,
    pub violation_code: u16,
    pub public_slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicCoverageSnapshot {
    pub target_block: u32,
    pub product_source_state: u32,
    pub product_target_state: u32,
    pub observer_divergence: Option<PublicObserverDivergence>,
    pub utility_violation: Option<PublicUtilityViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageFeedback {
    pub schema: String,
    pub records: Vec<CoverageRecord>,
    pub feedback_sha256: [u8; 32],
}

impl CoverageFeedback {
    pub fn from_public_transition(
        transition: &AdaptiveStateTransition,
        snapshot: PublicCoverageSnapshot,
    ) -> Result<Self, CoverageError> {
        let mut records = vec![
            CoverageRecord::build(CoveragePoint::TargetBlock {
                block_id: snapshot.target_block,
            })?,
            CoverageRecord::build(CoveragePoint::ProductState {
                source_state: snapshot.product_source_state,
                target_state: snapshot.product_target_state,
            })?,
            CoverageRecord::build(CoveragePoint::ContextState {
                step: transition.after.step,
                service_alias: transition.after.service_alias,
                connected: transition.after.connected,
                public_state_sha256: transition.after_sha256,
            })?,
        ];
        if let Some(divergence) = snapshot.observer_divergence {
            records.push(CoverageRecord::build(CoveragePoint::ObserverDivergence {
                observer_profile: divergence.observer_profile,
                divergence_code: divergence.divergence_code,
                public_trace_sha256: divergence.public_trace_sha256,
            })?);
        }
        if let Some(violation) = snapshot.utility_violation {
            records.push(CoverageRecord::build(CoveragePoint::UtilityViolation {
                obligation_id: violation.obligation_id,
                violation_code: violation.violation_code,
                public_slot: violation.public_slot,
            })?);
        }
        Self::build(records)
    }

    pub fn build(mut records: Vec<CoverageRecord>) -> Result<Self, CoverageError> {
        if records.is_empty() {
            return Err(CoverageError::EmptyFeedback);
        }
        if records.len() > MAX_FEEDBACK_RECORDS {
            return Err(CoverageError::FeedbackBound);
        }
        let mut seen = BTreeMap::new();
        for record in &records {
            if let Some(existing) = seen.get(&record.coverage_id) {
                if *existing != &record.point {
                    return Err(CoverageError::CoverageCollision);
                }
                return Err(CoverageError::DuplicateCoverage);
            }
            seen.insert(record.coverage_id, &record.point);
            record.validate()?;
        }
        records.sort_by_key(|record| record.coverage_id);
        let mut feedback = Self {
            schema: COVERAGE_FEEDBACK_SCHEMA.to_owned(),
            records,
            feedback_sha256: [0; 32],
        };
        feedback.feedback_sha256 = feedback.recomputed_sha256()?;
        Ok(feedback)
    }

    pub fn validate(&self) -> Result<(), CoverageError> {
        let expected = Self::build(self.records.clone())?;
        if self != &expected {
            return Err(CoverageError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, CoverageError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| CoverageError::Json)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], CoverageError> {
        let mut value = self.clone();
        value.feedback_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| CoverageError::Json)?;
        Ok(domain_hash(COVERAGE_FEEDBACK_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusBounds {
    pub max_entries: u32,
    pub max_coverage_points: u32,
    pub max_actions_per_entry: u32,
}

impl CorpusBounds {
    pub fn validate(self) -> Result<(), CoverageError> {
        if self.max_entries == 0
            || self.max_entries > HARD_MAX_ENTRIES
            || self.max_coverage_points == 0
            || self.max_coverage_points > HARD_MAX_COVERAGE_POINTS
            || self.max_actions_per_entry == 0
            || self.max_actions_per_entry > HARD_MAX_ACTIONS_PER_ENTRY
        {
            return Err(CoverageError::CorpusBounds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub seed: u64,
    pub action_program_sha256: [u8; 32],
    pub action_count: u32,
    pub feedback: CoverageFeedback,
    pub score: u32,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub entry_sha256: [u8; 32],
}

impl CorpusEntry {
    pub fn build(
        seed: u64,
        action_program_sha256: [u8; 32],
        action_count: u32,
        feedback: CoverageFeedback,
    ) -> Result<Self, CoverageError> {
        feedback.validate()?;
        if action_program_sha256 == [0; 32] || action_count == 0 {
            return Err(CoverageError::InvalidEntry);
        }
        let score =
            u32::try_from(feedback.records.len()).map_err(|_| CoverageError::FeedbackBound)?;
        let mut entry = Self {
            seed,
            action_program_sha256,
            action_count,
            feedback,
            score,
            evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            hardware_status: "NOT_VERIFIED".to_owned(),
            entry_sha256: [0; 32],
        };
        entry.entry_sha256 = entry.recomputed_sha256()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<(), CoverageError> {
        let expected = Self::build(
            self.seed,
            self.action_program_sha256,
            self.action_count,
            self.feedback.clone(),
        )?;
        if self != &expected {
            return Err(CoverageError::ArtifactMismatch);
        }
        Ok(())
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], CoverageError> {
        let mut value = self.clone();
        value.entry_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| CoverageError::Json)?;
        Ok(domain_hash(CORPUS_ENTRY_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusInsertDisposition {
    Inserted,
    Replaced,
    Duplicate,
    NoNewCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusInsertResult {
    pub disposition: CorpusInsertDisposition,
    pub novel_coverage: u32,
    pub retained_entries: u32,
    pub global_coverage: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicCorpus {
    pub schema: String,
    pub seed: u64,
    pub bounds: CorpusBounds,
    pub entries: Vec<CorpusEntry>,
    pub global_coverage: Vec<CoverageRecord>,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub artifact_sha256: [u8; 32],
}

impl DeterministicCorpus {
    pub fn new(seed: u64, bounds: CorpusBounds) -> Result<Self, CoverageError> {
        bounds.validate()?;
        let mut corpus = Self {
            schema: COVERAGE_CORPUS_SCHEMA.to_owned(),
            seed,
            bounds,
            entries: Vec::new(),
            global_coverage: Vec::new(),
            evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            hardware_status: "NOT_VERIFIED".to_owned(),
            artifact_sha256: [0; 32],
        };
        corpus.artifact_sha256 = corpus.recomputed_sha256()?;
        Ok(corpus)
    }

    pub fn insert(&mut self, entry: CorpusEntry) -> Result<CorpusInsertResult, CoverageError> {
        self.validate()?;
        entry.validate()?;
        if entry.action_count > self.bounds.max_actions_per_entry {
            return Err(CoverageError::ActionBound);
        }
        if let Some(existing) = self
            .entries
            .iter()
            .find(|existing| existing.entry_sha256 == entry.entry_sha256)
        {
            if existing != &entry {
                return Err(CoverageError::EntryCollision);
            }
            return Ok(self.result(CorpusInsertDisposition::Duplicate, 0));
        }

        let old_ids: BTreeSet<_> = self
            .global_coverage
            .iter()
            .map(|record| record.coverage_id)
            .collect();
        let novel_coverage = entry
            .feedback
            .records
            .iter()
            .filter(|record| !old_ids.contains(&record.coverage_id))
            .count();
        if novel_coverage == 0 {
            return Ok(self.result(CorpusInsertDisposition::NoNewCoverage, 0));
        }

        let old_entry_count = self.entries.len();
        let candidate_sha256 = entry.entry_sha256;
        let mut candidates = self.entries.clone();
        candidates.push(entry);
        let entries = canonical_entries(candidates)?;
        if entries.len() > self.bounds.max_entries as usize {
            return Err(CoverageError::CorpusEntryBound);
        }
        if !entries
            .iter()
            .any(|candidate| candidate.entry_sha256 == candidate_sha256)
        {
            return Ok(self.result(CorpusInsertDisposition::NoNewCoverage, 0));
        }
        let global_coverage = union_coverage(&entries)?;
        if global_coverage.len() > self.bounds.max_coverage_points as usize {
            return Err(CoverageError::CorpusCoverageBound);
        }
        let disposition = if entries.len() <= old_entry_count {
            CorpusInsertDisposition::Replaced
        } else {
            CorpusInsertDisposition::Inserted
        };
        self.entries = entries;
        self.global_coverage = global_coverage;
        self.artifact_sha256 = self.recomputed_sha256()?;
        Ok(self.result(
            disposition,
            u32::try_from(novel_coverage).map_err(|_| CoverageError::CorpusCoverageBound)?,
        ))
    }

    pub fn validate(&self) -> Result<(), CoverageError> {
        self.bounds.validate()?;
        if self.schema != COVERAGE_CORPUS_SCHEMA
            || self.evidence_origin != "INJECTED_TEST_FIXTURE"
            || self.hardware_status != "NOT_VERIFIED"
        {
            return Err(CoverageError::ArtifactMismatch);
        }
        for entry in &self.entries {
            entry.validate()?;
            if entry.action_count > self.bounds.max_actions_per_entry {
                return Err(CoverageError::ActionBound);
            }
        }
        let canonical = canonical_entries(self.entries.clone())?;
        if canonical != self.entries {
            return Err(CoverageError::NonCanonicalCorpus);
        }
        if self.entries.len() > self.bounds.max_entries as usize {
            return Err(CoverageError::CorpusEntryBound);
        }
        let expected_global = union_coverage(&self.entries)?;
        if expected_global != self.global_coverage {
            return Err(CoverageError::NonCanonicalCorpus);
        }
        if expected_global.len() > self.bounds.max_coverage_points as usize {
            return Err(CoverageError::CorpusCoverageBound);
        }
        if self.artifact_sha256 != self.recomputed_sha256()? {
            return Err(CoverageError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, CoverageError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| CoverageError::Json)
    }

    fn result(
        &self,
        disposition: CorpusInsertDisposition,
        novel_coverage: u32,
    ) -> CorpusInsertResult {
        CorpusInsertResult {
            disposition,
            novel_coverage,
            retained_entries: self.entries.len() as u32,
            global_coverage: self.global_coverage.len() as u32,
        }
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], CoverageError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| CoverageError::Json)?;
        Ok(domain_hash(CORPUS_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoverageError {
    #[error("coverage point is invalid")]
    InvalidPoint,
    #[error("coverage point digest mismatch")]
    CoverageDigestMismatch,
    #[error("coverage identifier collision")]
    CoverageCollision,
    #[error("duplicate coverage point")]
    DuplicateCoverage,
    #[error("coverage feedback is empty")]
    EmptyFeedback,
    #[error("coverage feedback exceeds its bound")]
    FeedbackBound,
    #[error("corpus bounds are invalid")]
    CorpusBounds,
    #[error("corpus entry is invalid")]
    InvalidEntry,
    #[error("corpus entry action bound was reached")]
    ActionBound,
    #[error("corpus entry bound was reached")]
    CorpusEntryBound,
    #[error("corpus coverage bound was reached")]
    CorpusCoverageBound,
    #[error("corpus entry identifier collision")]
    EntryCollision,
    #[error("coverage artifact failed full recomputation")]
    ArtifactMismatch,
    #[error("coverage corpus is not canonical")]
    NonCanonicalCorpus,
    #[error("coverage JSON serialization failed")]
    Json,
}

fn canonical_entries(mut entries: Vec<CorpusEntry>) -> Result<Vec<CorpusEntry>, CoverageError> {
    let mut ids = BTreeMap::new();
    for entry in &entries {
        if let Some(existing) = ids.insert(entry.entry_sha256, entry) {
            if existing != entry {
                return Err(CoverageError::EntryCollision);
            }
            return Err(CoverageError::NonCanonicalCorpus);
        }
    }
    entries.sort_by(entry_priority);
    let mut covered = BTreeSet::new();
    let mut retained = Vec::new();
    for entry in entries {
        let adds_coverage = entry
            .feedback
            .records
            .iter()
            .any(|record| !covered.contains(&record.coverage_id));
        if adds_coverage {
            covered.extend(
                entry
                    .feedback
                    .records
                    .iter()
                    .map(|record| record.coverage_id),
            );
            retained.push(entry);
        }
    }
    Ok(retained)
}

fn entry_priority(left: &CorpusEntry, right: &CorpusEntry) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.action_count.cmp(&right.action_count))
        .then_with(|| left.entry_sha256.cmp(&right.entry_sha256))
}

fn union_coverage(entries: &[CorpusEntry]) -> Result<Vec<CoverageRecord>, CoverageError> {
    let mut records: BTreeMap<[u8; 32], CoverageRecord> = BTreeMap::new();
    for entry in entries {
        for record in &entry.feedback.records {
            if let Some(existing) = records.get(&record.coverage_id) {
                if existing.point != record.point {
                    return Err(CoverageError::CoverageCollision);
                }
            } else {
                records.insert(record.coverage_id, record.clone());
            }
        }
    }
    Ok(records.into_values().collect())
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
