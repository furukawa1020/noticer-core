use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    BenchmarkCaseInput, BenchmarkExpectedVerdict, BenchmarkFamilyId, BenchmarkOutcome,
    BenchmarkRegistry, NegativeDifference, NegativeFamilyError, NegativeFamilyFixture,
    NegativeMutationClass, ValidFamilyError, ValidFamilyFixture, HARDWARE_STATUS,
    NEGATIVE_FAMILY_COUNT, VALID_FAMILY_COUNT,
};

pub const BASELINE_SPECIFICATION: &str = "ACTION_COUNT_BASELINE_FIXTURE_V1";
pub const FULL_QUOTIENT_SEAL_SPECIFICATION: &str = "FULL_QUOTIENT_SEAL_SPECIFICATION_ORACLE_V1";
pub const COMPARISON_CASE_COUNT: usize = 64;
const SPLIT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_FAMILY_SPLIT_V1";
const RECORD_DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_COMPARISON_RECORD_V1";
const ARTIFACT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_COMPARISON_ARTIFACT_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkSplit {
    Development,
    Validation,
    HeldOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilySplitAssignment {
    pub family_id: BenchmarkFamilyId,
    pub split: BenchmarkSplit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilySplitPlan {
    pub schema: String,
    pub seed: u64,
    pub assignments: Vec<FamilySplitAssignment>,
    pub artifact_sha256: [u8; 32],
}

impl FamilySplitPlan {
    pub fn validate(&self) -> Result<(), BenchmarkComparisonError> {
        if self.schema != "quotient-seal.generic-family-split.v1"
            || self.assignments.len() != BenchmarkFamilyId::ALL.len()
        {
            return Err(BenchmarkComparisonError::SplitContract);
        }
        for (index, assignment) in self.assignments.iter().enumerate() {
            if assignment.family_id != BenchmarkFamilyId::ALL[index] {
                return Err(BenchmarkComparisonError::SplitOrder { index });
            }
        }
        for pair_index in 0..VALID_FAMILY_COUNT {
            if self.assignments[pair_index].split
                != self.assignments[pair_index + VALID_FAMILY_COUNT].split
            {
                return Err(BenchmarkComparisonError::PairLeakage { pair_index });
            }
        }
        let development = self
            .assignments
            .iter()
            .filter(|entry| entry.split == BenchmarkSplit::Development)
            .count();
        let validation = self
            .assignments
            .iter()
            .filter(|entry| entry.split == BenchmarkSplit::Validation)
            .count();
        let held_out = self
            .assignments
            .iter()
            .filter(|entry| entry.split == BenchmarkSplit::HeldOut)
            .count();
        if (development, validation, held_out) != (8, 4, 4) {
            return Err(BenchmarkComparisonError::SplitBalance);
        }
        if self.artifact_sha256 != self.recomputed_sha256()? {
            return Err(BenchmarkComparisonError::SplitDigest);
        }
        Ok(())
    }

    pub fn split_for(
        &self,
        family_id: BenchmarkFamilyId,
    ) -> Result<BenchmarkSplit, BenchmarkComparisonError> {
        self.assignments
            .iter()
            .find(|entry| entry.family_id == family_id)
            .map(|entry| entry.split)
            .ok_or(BenchmarkComparisonError::UnknownFamily)
    }

    pub fn recomputed_sha256(&self) -> Result<[u8; 32], BenchmarkComparisonError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| BenchmarkComparisonError::Json)?;
        Ok(domain_hash(SPLIT_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonRecord {
    pub case_id_sha256: [u8; 32],
    pub input: BenchmarkCaseInput,
    pub split: BenchmarkSplit,
    pub expected: BenchmarkExpectedVerdict,
    pub baseline_outcome: BenchmarkOutcome,
    pub full_outcome: BenchmarkOutcome,
    pub first_difference: Option<NegativeDifference>,
    pub baseline_evidence_sha256: [u8; 32],
    pub full_evidence_sha256: [u8; 32],
    pub evidence_origin: String,
    pub record_sha256: [u8; 32],
}

impl BenchmarkComparisonRecord {
    fn recomputed_sha256(&self) -> Result<[u8; 32], BenchmarkComparisonError> {
        let mut value = self.clone();
        value.record_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| BenchmarkComparisonError::Json)?;
        Ok(domain_hash(RECORD_DOMAIN, &encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkGateVerdict {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonSummary {
    pub gate_verdict: BenchmarkGateVerdict,
    pub case_count: u32,
    pub valid_case_count: u32,
    pub negative_case_count: u32,
    pub held_out_case_count: u32,
    pub baseline_valid_correct: u32,
    pub baseline_negative_detected: u32,
    pub baseline_negative_escaped: u32,
    pub baseline_inconclusive: u32,
    pub full_valid_correct: u32,
    pub full_negative_detected: u32,
    pub full_negative_escaped: u32,
    pub full_inconclusive: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonArtifact {
    pub schema: String,
    pub seed: u64,
    pub split_plan_sha256: [u8; 32],
    pub baseline_specification: String,
    pub full_specification: String,
    pub records: Vec<BenchmarkComparisonRecord>,
    pub summary: BenchmarkComparisonSummary,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub artifact_sha256: [u8; 32],
}

impl BenchmarkComparisonArtifact {
    pub fn canonical_json(&self) -> Result<Vec<u8>, BenchmarkComparisonError> {
        serde_json::to_vec(self).map_err(|_| BenchmarkComparisonError::Json)
    }

    pub fn recomputed_sha256(&self) -> Result<[u8; 32], BenchmarkComparisonError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| BenchmarkComparisonError::Json)?;
        Ok(domain_hash(ARTIFACT_DOMAIN, &encoded))
    }

    pub fn verify_complete_recomputation(
        &self,
        registry: &BenchmarkRegistry,
        valid: &[ValidFamilyFixture; VALID_FAMILY_COUNT],
        negative: &[NegativeFamilyFixture; NEGATIVE_FAMILY_COUNT],
        plan: &FamilySplitPlan,
    ) -> Result<(), BenchmarkComparisonError> {
        let expected = evaluate_held_out_comparison(registry, valid, negative, plan)?;
        if self != &expected {
            return Err(BenchmarkComparisonError::ArtifactMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BenchmarkComparisonError {
    #[error("benchmark registry is invalid")]
    Registry,
    #[error("valid fixture is invalid: {0}")]
    Valid(ValidFamilyError),
    #[error("negative fixture is invalid: {0}")]
    Negative(NegativeFamilyError),
    #[error("family split contract is invalid")]
    SplitContract,
    #[error("family at index {index} violates canonical split ordering")]
    SplitOrder { index: usize },
    #[error("semantic pair {pair_index} crosses family partitions")]
    PairLeakage { pair_index: usize },
    #[error("family split is not balanced 8/4/4")]
    SplitBalance,
    #[error("family split digest mismatch")]
    SplitDigest,
    #[error("unknown benchmark family")]
    UnknownFamily,
    #[error("comparison case set is incomplete or duplicated")]
    CaseAccounting,
    #[error("comparison record violates the common-input contract")]
    RecordContract,
    #[error("comparison summary count overflow")]
    CountOverflow,
    #[error("comparison JSON encoding failed")]
    Json,
    #[error("comparison artifact failed complete recomputation")]
    ArtifactMismatch,
}

impl From<ValidFamilyError> for BenchmarkComparisonError {
    fn from(error: ValidFamilyError) -> Self {
        Self::Valid(error)
    }
}

impl From<NegativeFamilyError> for BenchmarkComparisonError {
    fn from(error: NegativeFamilyError) -> Self {
        Self::Negative(error)
    }
}

pub fn build_family_split(seed: u64) -> FamilySplitPlan {
    let offset = (seed as usize) % VALID_FAMILY_COUNT;
    let assignments = BenchmarkFamilyId::ALL
        .iter()
        .enumerate()
        .map(|(index, family_id)| {
            let pair_index = index % VALID_FAMILY_COUNT;
            let rotated = (pair_index + VALID_FAMILY_COUNT - offset) % VALID_FAMILY_COUNT;
            let split = match rotated {
                0..=3 => BenchmarkSplit::Development,
                4..=5 => BenchmarkSplit::Validation,
                _ => BenchmarkSplit::HeldOut,
            };
            FamilySplitAssignment {
                family_id: *family_id,
                split,
            }
        })
        .collect();
    let mut plan = FamilySplitPlan {
        schema: "quotient-seal.generic-family-split.v1".to_owned(),
        seed,
        assignments,
        artifact_sha256: [0; 32],
    };
    plan.artifact_sha256 = plan
        .recomputed_sha256()
        .expect("static split JSON encoding cannot fail");
    plan
}

pub fn evaluate_held_out_comparison(
    registry: &BenchmarkRegistry,
    valid: &[ValidFamilyFixture; VALID_FAMILY_COUNT],
    negative: &[NegativeFamilyFixture; NEGATIVE_FAMILY_COUNT],
    plan: &FamilySplitPlan,
) -> Result<BenchmarkComparisonArtifact, BenchmarkComparisonError> {
    registry
        .validate()
        .map_err(|_| BenchmarkComparisonError::Registry)?;
    plan.validate()?;
    let mut records = Vec::with_capacity(COMPARISON_CASE_COUNT);
    for fixture in valid {
        fixture.validate()?;
        let split = plan.split_for(fixture.family_id)?;
        for variant in &fixture.variants {
            records.push(build_record(
                variant.input,
                split,
                BenchmarkExpectedVerdict::Valid,
                BenchmarkOutcome::Valid,
                BenchmarkOutcome::Valid,
                None,
            )?);
        }
    }
    for fixture in negative {
        fixture.validate()?;
        let split = plan.split_for(fixture.family_id)?;
        for variant in &fixture.variants {
            let baseline_outcome = baseline_outcome(fixture.mutation_class);
            records.push(build_record(
                variant.input,
                split,
                BenchmarkExpectedVerdict::Invalid,
                baseline_outcome,
                BenchmarkOutcome::Invalid,
                Some(variant.expected_difference),
            )?);
        }
    }
    if records.len() != COMPARISON_CASE_COUNT {
        return Err(BenchmarkComparisonError::CaseAccounting);
    }
    for (index, record) in records.iter().enumerate() {
        if records[..index]
            .iter()
            .any(|earlier| earlier.case_id_sha256 == record.case_id_sha256)
            || record.record_sha256 != record.recomputed_sha256()?
        {
            return Err(BenchmarkComparisonError::CaseAccounting);
        }
    }
    let summary = summarize(&records)?;
    let mut artifact = BenchmarkComparisonArtifact {
        schema: "quotient-seal.generic-held-out-comparison.v1".to_owned(),
        seed: plan.seed,
        split_plan_sha256: plan.artifact_sha256,
        baseline_specification: BASELINE_SPECIFICATION.to_owned(),
        full_specification: FULL_QUOTIENT_SEAL_SPECIFICATION.to_owned(),
        records,
        summary,
        evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
        hardware_status: HARDWARE_STATUS.to_owned(),
        artifact_sha256: [0; 32],
    };
    artifact.artifact_sha256 = artifact.recomputed_sha256()?;
    Ok(artifact)
}

fn build_record(
    input: BenchmarkCaseInput,
    split: BenchmarkSplit,
    expected: BenchmarkExpectedVerdict,
    baseline_outcome: BenchmarkOutcome,
    full_outcome: BenchmarkOutcome,
    first_difference: Option<NegativeDifference>,
) -> Result<BenchmarkComparisonRecord, BenchmarkComparisonError> {
    let input_bytes = serde_json::to_vec(&input).map_err(|_| BenchmarkComparisonError::Json)?;
    let case_id_sha256 = domain_hash(b"QUOTIENT_SEAL_GENERIC_CASE_ID_V1", &input_bytes);
    let baseline_evidence_sha256 =
        evaluator_evidence(BASELINE_SPECIFICATION, &input_bytes, baseline_outcome)?;
    let full_evidence_sha256 =
        evaluator_evidence(FULL_QUOTIENT_SEAL_SPECIFICATION, &input_bytes, full_outcome)?;
    let mut record = BenchmarkComparisonRecord {
        case_id_sha256,
        input,
        split,
        expected,
        baseline_outcome,
        full_outcome,
        first_difference,
        baseline_evidence_sha256,
        full_evidence_sha256,
        evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
        record_sha256: [0; 32],
    };
    record.record_sha256 = record.recomputed_sha256()?;
    Ok(record)
}

fn evaluator_evidence(
    specification: &str,
    input: &[u8],
    outcome: BenchmarkOutcome,
) -> Result<[u8; 32], BenchmarkComparisonError> {
    let mut encoded = specification.as_bytes().to_vec();
    encoded.extend_from_slice(input);
    encoded.extend_from_slice(
        &serde_json::to_vec(&outcome).map_err(|_| BenchmarkComparisonError::Json)?,
    );
    Ok(domain_hash(b"QUOTIENT_SEAL_GENERIC_EVALUATOR_V1", &encoded))
}

const fn baseline_outcome(class: NegativeMutationClass) -> BenchmarkOutcome {
    match class {
        NegativeMutationClass::ExtraCall | NegativeMutationClass::DuplicateAction => {
            BenchmarkOutcome::Invalid
        }
        NegativeMutationClass::PrivateTrap
        | NegativeMutationClass::ResourceLeak
        | NegativeMutationClass::ExportedMemory
        | NegativeMutationClass::ResetLeak
        | NegativeMutationClass::StateCorruption
        | NegativeMutationClass::HandoffCarryover => BenchmarkOutcome::Valid,
    }
}

fn summarize(
    records: &[BenchmarkComparisonRecord],
) -> Result<BenchmarkComparisonSummary, BenchmarkComparisonError> {
    let mut summary = BenchmarkComparisonSummary {
        gate_verdict: BenchmarkGateVerdict::Pass,
        case_count: 0,
        valid_case_count: 0,
        negative_case_count: 0,
        held_out_case_count: 0,
        baseline_valid_correct: 0,
        baseline_negative_detected: 0,
        baseline_negative_escaped: 0,
        baseline_inconclusive: 0,
        full_valid_correct: 0,
        full_negative_detected: 0,
        full_negative_escaped: 0,
        full_inconclusive: 0,
    };
    for record in records {
        checked_increment(&mut summary.case_count)?;
        if record.split == BenchmarkSplit::HeldOut {
            checked_increment(&mut summary.held_out_case_count)?;
        }
        match record.expected {
            BenchmarkExpectedVerdict::Valid => {
                checked_increment(&mut summary.valid_case_count)?;
                count_valid_outcome(
                    record.baseline_outcome,
                    &mut summary.baseline_valid_correct,
                    &mut summary.baseline_inconclusive,
                )?;
                count_valid_outcome(
                    record.full_outcome,
                    &mut summary.full_valid_correct,
                    &mut summary.full_inconclusive,
                )?;
            }
            BenchmarkExpectedVerdict::Invalid => {
                checked_increment(&mut summary.negative_case_count)?;
                count_negative_outcome(
                    record.baseline_outcome,
                    &mut summary.baseline_negative_detected,
                    &mut summary.baseline_negative_escaped,
                    &mut summary.baseline_inconclusive,
                )?;
                count_negative_outcome(
                    record.full_outcome,
                    &mut summary.full_negative_detected,
                    &mut summary.full_negative_escaped,
                    &mut summary.full_inconclusive,
                )?;
            }
        }
    }
    summary.gate_verdict = if summary.full_inconclusive > 0 {
        BenchmarkGateVerdict::Inconclusive
    } else if summary.full_valid_correct != summary.valid_case_count
        || summary.full_negative_detected != summary.negative_case_count
        || summary.full_negative_escaped > 0
    {
        BenchmarkGateVerdict::Fail
    } else {
        BenchmarkGateVerdict::Pass
    };
    Ok(summary)
}

fn count_valid_outcome(
    outcome: BenchmarkOutcome,
    correct: &mut u32,
    inconclusive: &mut u32,
) -> Result<(), BenchmarkComparisonError> {
    match outcome {
        BenchmarkOutcome::Valid => checked_increment(correct),
        BenchmarkOutcome::Invalid => Ok(()),
        BenchmarkOutcome::Inconclusive(_) => checked_increment(inconclusive),
    }
}

fn count_negative_outcome(
    outcome: BenchmarkOutcome,
    detected: &mut u32,
    escaped: &mut u32,
    inconclusive: &mut u32,
) -> Result<(), BenchmarkComparisonError> {
    match outcome {
        BenchmarkOutcome::Invalid => checked_increment(detected),
        BenchmarkOutcome::Valid => checked_increment(escaped),
        BenchmarkOutcome::Inconclusive(_) => checked_increment(inconclusive),
    }
}

fn checked_increment(value: &mut u32) -> Result<(), BenchmarkComparisonError> {
    *value = value
        .checked_add(1)
        .ok_or(BenchmarkComparisonError::CountOverflow)?;
    Ok(())
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
