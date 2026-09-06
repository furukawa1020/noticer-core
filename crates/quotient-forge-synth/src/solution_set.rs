//! Exhaustive small-model comparison of unreduced and quotient solution sets.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::lift::{
    lift_reduced_candidate, LiftCheckerDecision, LiftMapping, LiftedCandidate,
    LiftedCandidateChecker, QuotientLiftError, ReducedCandidate, ReducedPolicyCell,
};
use crate::preservation::QuotientPreservationArtifact;
use crate::quotient::QuotientPartition;

pub const SOLUTION_SET_EQUIVALENCE_SCHEMA_V1: &str =
    "noticer.quotient_forge.solution_set_equivalence.v1";
const MAX_ENUMERATION_CELLS: u32 = 16;
const MAX_CONTROL_STATES: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FrozenEnumerationDomain {
    pub seed: u64,
    pub control_state_count: u32,
    pub symbol_count: u32,
    pub output_count: u32,
    pub max_candidates_per_side: u64,
}

impl FrozenEnumerationDomain {
    pub fn new(
        seed: u64,
        control_state_count: u32,
        symbol_count: u32,
        output_count: u32,
        max_candidates_per_side: u64,
    ) -> Result<Self, SolutionSetError> {
        let domain = Self {
            seed,
            control_state_count,
            symbol_count,
            output_count,
            max_candidates_per_side,
        };
        domain.validate_dimensions()?;
        Ok(domain)
    }

    fn validate_dimensions(&self) -> Result<(), SolutionSetError> {
        if self.control_state_count == 0
            || self.symbol_count == 0
            || self.output_count == 0
            || self.max_candidates_per_side == 0
            || self.control_state_count > MAX_CONTROL_STATES
        {
            return Err(SolutionSetError::InvalidDomain);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourcePolicyCell {
    pub control_state: u32,
    pub source_ordinal: u32,
    pub symbol_id: u32,
    pub next_control_state: u32,
    pub output_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCandidate {
    pub control_state_count: u32,
    pub source_state_count: u32,
    pub symbol_count: u32,
    pub cells: Vec<SourcePolicyCell>,
}

#[derive(Serialize)]
struct CanonicalSourceCandidate<'a> {
    control_state_count: u32,
    source_state_count: u32,
    symbol_count: u32,
    cells: Vec<CanonicalSourceCell<'a>>,
}

#[derive(Serialize)]
struct CanonicalSourceCell<'a> {
    control_state: u32,
    source_ordinal: u32,
    symbol_id: u32,
    next_control_state: u32,
    output_sha256: &'a str,
}

impl SourceCandidate {
    pub fn new(
        control_state_count: u32,
        source_state_count: u32,
        symbol_count: u32,
        mut cells: Vec<SourcePolicyCell>,
    ) -> Result<Self, SolutionSetError> {
        cells.sort();
        let candidate = Self {
            control_state_count,
            source_state_count,
            symbol_count,
            cells,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn cell(
        &self,
        control_state: u32,
        source_ordinal: u32,
        symbol_id: u32,
    ) -> &SourcePolicyCell {
        let row_width = self.source_state_count * self.symbol_count;
        let index = control_state * row_width + source_ordinal * self.symbol_count + symbol_id;
        &self.cells[index as usize]
    }

    pub fn canonical_solution_sha256(&self) -> Result<String, SolutionSetError> {
        self.validate()?;
        let mut permutations = Vec::new();
        let mut current = vec![0];
        let mut remaining = (1..self.control_state_count).collect::<Vec<_>>();
        enumerate_permutations(&mut current, &mut remaining, &mut permutations);
        let mut minimum = None::<Vec<u8>>;
        for old_to_new in permutations {
            let bytes = self.canonical_bytes_under(&old_to_new)?;
            if minimum.as_ref().is_none_or(|prior| bytes < *prior) {
                minimum = Some(bytes);
            }
        }
        let bytes = minimum.ok_or(SolutionSetError::InvalidSourceCandidate)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn from_lifted(candidate: &LiftedCandidate) -> Result<Self, SolutionSetError> {
        let source_ordinals = candidate
            .cells
            .iter()
            .map(|cell| cell.source_index)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(ordinal, source_index)| {
                u32::try_from(ordinal)
                    .map(|ordinal| (source_index, ordinal))
                    .map_err(|_| SolutionSetError::ModelTooLarge)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let cells = candidate
            .cells
            .iter()
            .map(|cell| SourcePolicyCell {
                control_state: cell.control_state,
                source_ordinal: source_ordinals[&cell.source_index],
                symbol_id: cell.symbol_id,
                next_control_state: cell.next_control_state,
                output_sha256: cell.output_sha256.clone(),
            })
            .collect();
        Self::new(
            candidate.control_state_count,
            candidate.source_state_count,
            candidate.symbol_count,
            cells,
        )
    }

    fn validate(&self) -> Result<(), SolutionSetError> {
        if self.control_state_count == 0 || self.source_state_count == 0 || self.symbol_count == 0 {
            return Err(SolutionSetError::InvalidSourceCandidate);
        }
        let expected = u64::from(self.control_state_count)
            .checked_mul(u64::from(self.source_state_count))
            .and_then(|value| value.checked_mul(u64::from(self.symbol_count)))
            .ok_or(SolutionSetError::ModelTooLarge)?;
        if u64::try_from(self.cells.len()).map_err(|_| SolutionSetError::ModelTooLarge)? != expected
        {
            return Err(SolutionSetError::InvalidSourceCandidate);
        }
        let mut expected_keys = (0..self.control_state_count).flat_map(|control_state| {
            (0..self.source_state_count).flat_map(move |source_ordinal| {
                (0..self.symbol_count)
                    .map(move |symbol_id| (control_state, source_ordinal, symbol_id))
            })
        });
        for cell in &self.cells {
            if cell.next_control_state >= self.control_state_count
                || Some((cell.control_state, cell.source_ordinal, cell.symbol_id))
                    != expected_keys.next()
                || !is_sha256(&cell.output_sha256)
            {
                return Err(SolutionSetError::InvalidSourceCandidate);
            }
        }
        Ok(())
    }

    fn canonical_bytes_under(&self, old_to_new: &[u32]) -> Result<Vec<u8>, SolutionSetError> {
        let mut new_to_old = vec![0_u32; old_to_new.len()];
        for (old, new) in old_to_new.iter().copied().enumerate() {
            new_to_old[new as usize] =
                u32::try_from(old).map_err(|_| SolutionSetError::ModelTooLarge)?;
        }
        let mut cells = Vec::with_capacity(self.cells.len());
        for new_control_state in 0..self.control_state_count {
            let old_control_state = new_to_old[new_control_state as usize];
            for source_ordinal in 0..self.source_state_count {
                for symbol_id in 0..self.symbol_count {
                    let old = self.cell(old_control_state, source_ordinal, symbol_id);
                    cells.push(CanonicalSourceCell {
                        control_state: new_control_state,
                        source_ordinal,
                        symbol_id,
                        next_control_state: old_to_new[old.next_control_state as usize],
                        output_sha256: &old.output_sha256,
                    });
                }
            }
        }
        serde_json::to_vec(&CanonicalSourceCandidate {
            control_state_count: self.control_state_count,
            source_state_count: self.source_state_count,
            symbol_count: self.symbol_count,
            cells,
        })
        .map_err(|_| SolutionSetError::Serialization)
    }
}

pub trait SmallModelSolutionChecker {
    fn check_unreduced(&self, candidate: &SourceCandidate) -> LiftCheckerDecision;
    fn check_reduced(&self, candidate: &ReducedCandidate) -> LiftCheckerDecision;
}

struct LiftCheckerAdapter<'a, C> {
    checker: &'a C,
}

impl<C: SmallModelSolutionChecker> LiftedCandidateChecker for LiftCheckerAdapter<'_, C> {
    fn check(
        &self,
        _partition: &QuotientPartition,
        _mapping: &LiftMapping,
        _reduced_candidate: &ReducedCandidate,
        lifted_candidate: &LiftedCandidate,
    ) -> LiftCheckerDecision {
        SourceCandidate::from_lifted(lifted_candidate)
            .map_or(LiftCheckerDecision::Invalid, |candidate| {
                self.checker.check_unreduced(&candidate)
            })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolutionSetStatus {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolutionDifferenceKind {
    Missing,
    Spurious,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolutionDifferenceWitness {
    pub kind: SolutionDifferenceKind,
    pub canonical_solution_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolutionSetEquivalenceArtifact {
    pub schema_version: String,
    pub problem_sha256: String,
    pub quotient_artifact_sha256: String,
    pub preservation_artifact_sha256: String,
    pub mapping_commitment_sha256: String,
    pub frozen_domain_sha256: String,
    pub seed: u64,
    pub control_state_count: u32,
    pub source_state_count: u32,
    pub quotient_class_count: u32,
    pub symbol_count: u32,
    pub output_count: u32,
    pub max_candidates_per_side: u64,
    pub unreduced_generated_candidates: u64,
    pub reduced_generated_candidates: u64,
    pub unreduced_checker_calls: u64,
    pub reduced_checker_calls: u64,
    pub lift_checker_calls: u64,
    pub unreduced_valid_candidates: u64,
    pub reduced_valid_candidates: u64,
    pub checker_inconclusive_count: u64,
    pub checker_disagreement_count: u64,
    pub unreduced_solution_sha256: Vec<String>,
    pub reduced_lifted_solution_sha256: Vec<String>,
    pub missing_solution_sha256: Vec<String>,
    pub spurious_solution_sha256: Vec<String>,
    pub missing_witness: Option<SolutionDifferenceWitness>,
    pub spurious_witness: Option<SolutionDifferenceWitness>,
    pub sets_equal: bool,
    pub status: SolutionSetStatus,
    pub private_values_included: bool,
    pub artifact_sha256: String,
}

impl SolutionSetEquivalenceArtifact {
    pub fn validate(&self) -> Result<(), SolutionSetError> {
        if self.schema_version != SOLUTION_SET_EQUIVALENCE_SCHEMA_V1 {
            return Err(SolutionSetError::SchemaVersion);
        }
        for value in [
            &self.problem_sha256,
            &self.quotient_artifact_sha256,
            &self.preservation_artifact_sha256,
            &self.mapping_commitment_sha256,
            &self.frozen_domain_sha256,
            &self.artifact_sha256,
        ] {
            if !is_sha256(value) {
                return Err(SolutionSetError::InvalidArtifact);
            }
        }
        for set in [
            &self.unreduced_solution_sha256,
            &self.reduced_lifted_solution_sha256,
            &self.missing_solution_sha256,
            &self.spurious_solution_sha256,
        ] {
            if set.iter().any(|value| !is_sha256(value))
                || set.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(SolutionSetError::InvalidArtifact);
            }
        }
        let domain = FrozenEnumerationDomain::new(
            self.seed,
            self.control_state_count,
            self.symbol_count,
            self.output_count,
            self.max_candidates_per_side,
        )?;
        let expected_domain_sha256 =
            domain_digest(&domain, self.source_state_count, self.quotient_class_count)?;
        let (_, expected_unreduced) = candidate_domain_size(
            &domain,
            self.source_state_count,
            self.max_candidates_per_side,
        )?;
        let (_, expected_reduced) = candidate_domain_size(
            &domain,
            self.quotient_class_count,
            self.max_candidates_per_side,
        )?;
        if expected_domain_sha256 != self.frozen_domain_sha256
            || self.unreduced_generated_candidates != expected_unreduced
            || self.reduced_generated_candidates != expected_reduced
            || self.unreduced_checker_calls != expected_unreduced
            || self.reduced_checker_calls != expected_reduced
            || self.lift_checker_calls != expected_reduced
            || self.unreduced_valid_candidates > expected_unreduced
            || self.reduced_valid_candidates > expected_reduced
            || self.unreduced_solution_sha256.len() as u64 > self.unreduced_valid_candidates
            || self.reduced_lifted_solution_sha256.len() as u64 > self.reduced_valid_candidates
            || self.checker_disagreement_count > expected_reduced
            || self.private_values_included
        {
            return Err(SolutionSetError::InvalidArtifact);
        }
        let unreduced = self
            .unreduced_solution_sha256
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let reduced = self
            .reduced_lifted_solution_sha256
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let missing = unreduced.difference(&reduced).cloned().collect::<Vec<_>>();
        let spurious = reduced.difference(&unreduced).cloned().collect::<Vec<_>>();
        if missing != self.missing_solution_sha256
            || spurious != self.spurious_solution_sha256
            || self.sets_equal != (missing.is_empty() && spurious.is_empty())
            || !witness_matches(
                &self.missing_witness,
                SolutionDifferenceKind::Missing,
                missing.first(),
            )
            || !witness_matches(
                &self.spurious_witness,
                SolutionDifferenceKind::Spurious,
                spurious.first(),
            )
        {
            return Err(SolutionSetError::InvalidArtifact);
        }
        let expected_status = if self.checker_inconclusive_count > 0 {
            SolutionSetStatus::Inconclusive
        } else if !self.sets_equal || self.checker_disagreement_count > 0 {
            SolutionSetStatus::Fail
        } else {
            SolutionSetStatus::Pass
        };
        if self.status != expected_status {
            return Err(SolutionSetError::InvalidArtifact);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(SolutionSetError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SolutionSetError {
    #[error("frozen enumeration domain is invalid")]
    InvalidDomain,
    #[error("enumeration domain has {cells} cells, exceeding the fixed cell bound")]
    CellBoundExceeded { cells: u32 },
    #[error("enumeration requires {required} candidates, exceeding limit {limit}")]
    CandidateBoundExceeded { required: u64, limit: u64 },
    #[error("source candidate is malformed")]
    InvalidSourceCandidate,
    #[error("model exceeds representable artifact bounds")]
    ModelTooLarge,
    #[error("quotient lift failed: {0}")]
    QuotientLift(#[from] QuotientLiftError),
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("solution-set equivalence artifact is inconsistent")]
    InvalidArtifact,
    #[error("artifact digest does not match its canonical payload")]
    DigestMismatch,
    #[error("canonical serialization failed")]
    Serialization,
}

pub fn compare_small_model_solution_sets<C: SmallModelSolutionChecker>(
    problem_sha256: impl Into<String>,
    domain: FrozenEnumerationDomain,
    partition: &QuotientPartition,
    preservation: &QuotientPreservationArtifact,
    mapping: &LiftMapping,
    checker: &C,
) -> Result<SolutionSetEquivalenceArtifact, SolutionSetError> {
    domain.validate_dimensions()?;
    let problem_sha256 = problem_sha256.into();
    if !is_sha256(&problem_sha256) {
        return Err(SolutionSetError::InvalidArtifact);
    }
    let source_state_count = u32::try_from(partition.mapped_state_count())
        .map_err(|_| SolutionSetError::ModelTooLarge)?;
    let quotient_class_count = u32::try_from(partition.artifact.classes.len())
        .map_err(|_| SolutionSetError::ModelTooLarge)?;
    let (unreduced_cells, unreduced_count) =
        candidate_domain_size(&domain, source_state_count, domain.max_candidates_per_side)?;
    let (reduced_cells, reduced_count) = candidate_domain_size(
        &domain,
        quotient_class_count,
        domain.max_candidates_per_side,
    )?;
    let choices = seeded_choices(&domain);
    let adapter = LiftCheckerAdapter { checker };
    let mut reduced_solutions = BTreeSet::new();
    let mut reduced_valid_candidates = 0_u64;
    let mut checker_inconclusive_count = 0_u64;
    let mut checker_disagreement_count = 0_u64;

    for rank in 0..reduced_count {
        let decisions = decode_candidate(rank, reduced_cells, &choices);
        let reduced = build_reduced_candidate(&domain, quotient_class_count, &decisions)?;
        let reduced_decision = checker.check_reduced(&reduced);
        if reduced_decision == LiftCheckerDecision::Inconclusive {
            checker_inconclusive_count += 1;
        }
        if reduced_decision == LiftCheckerDecision::Valid {
            reduced_valid_candidates += 1;
        }
        let lifted = lift_reduced_candidate(
            &problem_sha256,
            partition,
            preservation,
            mapping,
            &reduced,
            &adapter,
        )?;
        let lift_decision = lifted.artifact.checker_decision;
        if lift_decision == LiftCheckerDecision::Inconclusive {
            checker_inconclusive_count += 1;
        }
        if lift_decision != reduced_decision {
            checker_disagreement_count += 1;
        }
        if reduced_decision == LiftCheckerDecision::Valid {
            reduced_solutions.insert(
                SourceCandidate::from_lifted(&lifted.lifted_candidate)?
                    .canonical_solution_sha256()?,
            );
        }
    }

    let mut unreduced_solutions = BTreeSet::new();
    let mut unreduced_valid_candidates = 0_u64;
    for rank in 0..unreduced_count {
        let decisions = decode_candidate(rank, unreduced_cells, &choices);
        let candidate = build_source_candidate(&domain, source_state_count, &decisions)?;
        let decision = checker.check_unreduced(&candidate);
        if decision == LiftCheckerDecision::Inconclusive {
            checker_inconclusive_count += 1;
        }
        if decision == LiftCheckerDecision::Valid {
            unreduced_valid_candidates += 1;
            unreduced_solutions.insert(candidate.canonical_solution_sha256()?);
        }
    }

    let missing = unreduced_solutions
        .difference(&reduced_solutions)
        .cloned()
        .collect::<Vec<_>>();
    let spurious = reduced_solutions
        .difference(&unreduced_solutions)
        .cloned()
        .collect::<Vec<_>>();
    let sets_equal = missing.is_empty() && spurious.is_empty();
    let status = if checker_inconclusive_count > 0 {
        SolutionSetStatus::Inconclusive
    } else if !sets_equal || checker_disagreement_count > 0 {
        SolutionSetStatus::Fail
    } else {
        SolutionSetStatus::Pass
    };
    let missing_witness = missing.first().map(|digest| SolutionDifferenceWitness {
        kind: SolutionDifferenceKind::Missing,
        canonical_solution_sha256: digest.clone(),
    });
    let spurious_witness = spurious.first().map(|digest| SolutionDifferenceWitness {
        kind: SolutionDifferenceKind::Spurious,
        canonical_solution_sha256: digest.clone(),
    });
    let mut artifact = SolutionSetEquivalenceArtifact {
        schema_version: SOLUTION_SET_EQUIVALENCE_SCHEMA_V1.to_owned(),
        problem_sha256,
        quotient_artifact_sha256: partition.artifact.artifact_sha256.clone(),
        preservation_artifact_sha256: preservation.artifact_sha256.clone(),
        mapping_commitment_sha256: mapping.mapping_commitment_sha256().to_owned(),
        frozen_domain_sha256: domain_digest(&domain, source_state_count, quotient_class_count)?,
        seed: domain.seed,
        control_state_count: domain.control_state_count,
        source_state_count,
        quotient_class_count,
        symbol_count: domain.symbol_count,
        output_count: domain.output_count,
        max_candidates_per_side: domain.max_candidates_per_side,
        unreduced_generated_candidates: unreduced_count,
        reduced_generated_candidates: reduced_count,
        unreduced_checker_calls: unreduced_count,
        reduced_checker_calls: reduced_count,
        lift_checker_calls: reduced_count,
        unreduced_valid_candidates,
        reduced_valid_candidates,
        checker_inconclusive_count,
        checker_disagreement_count,
        unreduced_solution_sha256: unreduced_solutions.into_iter().collect(),
        reduced_lifted_solution_sha256: reduced_solutions.into_iter().collect(),
        missing_solution_sha256: missing,
        spurious_solution_sha256: spurious,
        missing_witness,
        spurious_witness,
        sets_equal,
        status,
        private_values_included: false,
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate()?;
    Ok(artifact)
}

fn candidate_domain_size(
    domain: &FrozenEnumerationDomain,
    indexed_state_count: u32,
    limit: u64,
) -> Result<(u32, u64), SolutionSetError> {
    if indexed_state_count == 0 {
        return Err(SolutionSetError::InvalidDomain);
    }
    let cells = domain
        .control_state_count
        .checked_mul(indexed_state_count)
        .and_then(|value| value.checked_mul(domain.symbol_count))
        .ok_or(SolutionSetError::ModelTooLarge)?;
    if cells > MAX_ENUMERATION_CELLS {
        return Err(SolutionSetError::CellBoundExceeded { cells });
    }
    let choices = u64::from(domain.control_state_count)
        .checked_mul(u64::from(domain.output_count))
        .ok_or(SolutionSetError::ModelTooLarge)?;
    let required = choices
        .checked_pow(cells)
        .ok_or(SolutionSetError::ModelTooLarge)?;
    if required > limit {
        return Err(SolutionSetError::CandidateBoundExceeded { required, limit });
    }
    Ok((cells, required))
}

fn seeded_choices(domain: &FrozenEnumerationDomain) -> Vec<(u32, u32)> {
    let mut choices = (0..domain.control_state_count)
        .flat_map(|next_state| (0..domain.output_count).map(move |output| (next_state, output)))
        .collect::<Vec<_>>();
    let offset = usize::try_from(domain.seed % choices.len() as u64).unwrap_or(0);
    choices.rotate_left(offset);
    choices
}

fn decode_candidate(rank: u64, cells: u32, choices: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut value = rank;
    let radix = choices.len() as u64;
    (0..cells)
        .map(|_| {
            let choice = choices[(value % radix) as usize];
            value /= radix;
            choice
        })
        .collect()
}

fn build_reduced_candidate(
    domain: &FrozenEnumerationDomain,
    class_count: u32,
    decisions: &[(u32, u32)],
) -> Result<ReducedCandidate, SolutionSetError> {
    let mut cells = Vec::with_capacity(decisions.len());
    for control_state in 0..domain.control_state_count {
        for class_id in 0..class_count {
            for symbol_id in 0..domain.symbol_count {
                let index = (control_state * class_count * domain.symbol_count
                    + class_id * domain.symbol_count
                    + symbol_id) as usize;
                let (next_control_state, output) = decisions[index];
                cells.push(ReducedPolicyCell::new(
                    control_state,
                    class_id,
                    symbol_id,
                    next_control_state,
                    output_digest(output),
                )?);
            }
        }
    }
    ReducedCandidate::new(
        domain.control_state_count,
        class_count,
        domain.symbol_count,
        cells,
    )
    .map_err(Into::into)
}

fn build_source_candidate(
    domain: &FrozenEnumerationDomain,
    source_count: u32,
    decisions: &[(u32, u32)],
) -> Result<SourceCandidate, SolutionSetError> {
    let mut cells = Vec::with_capacity(decisions.len());
    for control_state in 0..domain.control_state_count {
        for source_ordinal in 0..source_count {
            for symbol_id in 0..domain.symbol_count {
                let index = (control_state * source_count * domain.symbol_count
                    + source_ordinal * domain.symbol_count
                    + symbol_id) as usize;
                let (next_control_state, output) = decisions[index];
                cells.push(SourcePolicyCell {
                    control_state,
                    source_ordinal,
                    symbol_id,
                    next_control_state,
                    output_sha256: output_digest(output),
                });
            }
        }
    }
    SourceCandidate::new(
        domain.control_state_count,
        source_count,
        domain.symbol_count,
        cells,
    )
}

#[derive(Serialize)]
struct BoundDomain<'a> {
    domain: &'a FrozenEnumerationDomain,
    source_state_count: u32,
    quotient_class_count: u32,
}

fn domain_digest(
    domain: &FrozenEnumerationDomain,
    source_state_count: u32,
    quotient_class_count: u32,
) -> Result<String, SolutionSetError> {
    canonical_json_sha256(&BoundDomain {
        domain,
        source_state_count,
        quotient_class_count,
    })
}

fn enumerate_permutations(
    current: &mut Vec<u32>,
    remaining: &mut Vec<u32>,
    output: &mut Vec<Vec<u32>>,
) {
    if remaining.is_empty() {
        output.push(current.clone());
        return;
    }
    for index in 0..remaining.len() {
        let value = remaining.remove(index);
        current.push(value);
        enumerate_permutations(current, remaining, output);
        current.pop();
        remaining.insert(index, value);
    }
}

fn witness_matches(
    witness: &Option<SolutionDifferenceWitness>,
    kind: SolutionDifferenceKind,
    expected: Option<&String>,
) -> bool {
    match (witness, expected) {
        (None, None) => true,
        (Some(witness), Some(expected)) => {
            witness.kind == kind && witness.canonical_solution_sha256 == *expected
        }
        _ => false,
    }
}

fn output_digest(output: u32) -> String {
    format!("{output:064x}")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, SolutionSetError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SolutionSetError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
