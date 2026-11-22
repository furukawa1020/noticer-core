//! End-to-end paired comparison, uncertainty, claim gate, and capsule engine.

use crate::trial_bootstrap::{paired_mean_interval, BootstrapError};
use crate::trial_claim_gate::{authorize, ClaimEvidence};
use crate::trial_noninferiority::NonInferiorityResult;
use crate::trial_public_capsule::{PublicTrialCapsule, PublicTrialCapsuleInput};
use crate::trial_verdict::{InconclusiveTrial, InvalidTrial, TrialVerdict};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientTrialInput {
    pub paired_differences: Vec<i64>,
    pub seed: u64,
    pub resamples: u32,
    pub manifest_digest: [u8; 32],
    pub meaningful_threshold: u64,
    pub matrix_complete: bool,
    pub authenticated: bool,
    pub multiplicity_corrected: bool,
    pub censoring_count: u32,
    pub censoring_disclosed: bool,
    pub noninferiority: NonInferiorityResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientTrialResult {
    pub verdict: TrialVerdict,
    pub capsule: Option<PublicTrialCapsule>,
}

pub fn run(input: QuotientTrialInput) -> QuotientTrialResult {
    if input.manifest_digest == [0; 32] {
        return QuotientTrialResult {
            verdict: TrialVerdict::Invalid(InvalidTrial::ContractMismatch),
            capsule: None,
        };
    }
    let interval =
        match paired_mean_interval(&input.paired_differences, input.seed, input.resamples) {
            Ok(value) => value,
            Err(BootstrapError::Empty | BootstrapError::ZeroResamples) => {
                return QuotientTrialResult {
                    verdict: TrialVerdict::Inconclusive(InconclusiveTrial::InsufficientRepetitions),
                    capsule: None,
                };
            }
            Err(BootstrapError::Overflow) => {
                return QuotientTrialResult {
                    verdict: TrialVerdict::Invalid(InvalidTrial::MalformedSample),
                    capsule: None,
                };
            }
        };
    let excludes_null = interval.lower > 0 || interval.upper < 0;
    let evidence = ClaimEvidence {
        reproducible: true,
        matrix_complete: input.matrix_complete,
        authenticated: input.authenticated,
        confidence_interval_excludes_null: excludes_null,
        meaningful_effect: interval.estimate.unsigned_abs() >= input.meaningful_threshold,
        noninferiority: input.noninferiority,
        multiplicity_corrected: input.multiplicity_corrected,
        censoring_disclosed: input.censoring_disclosed,
    };
    let claim_authorized = authorize(evidence).is_ok();
    let verdict = if claim_authorized {
        TrialVerdict::Pass
    } else {
        TrialVerdict::Fail
    };
    let capsule = PublicTrialCapsule::new(PublicTrialCapsuleInput {
        verdict,
        comparison_label: "paired-effect".into(),
        estimate: interval.estimate,
        lower_bound: interval.lower,
        upper_bound: interval.upper,
        unit: "integer-units".into(),
        manifest_digest: input.manifest_digest,
        claim_authorized,
        censoring_count: input.censoring_count,
    })
    .ok();
    QuotientTrialResult { verdict, capsule }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> QuotientTrialInput {
        QuotientTrialInput {
            paired_differences: vec![-10, -11, -9, -10],
            seed: 7,
            resamples: 100,
            manifest_digest: [1; 32],
            meaningful_threshold: 5,
            matrix_complete: true,
            authenticated: true,
            multiplicity_corrected: true,
            censoring_count: 0,
            censoring_disclosed: true,
            noninferiority: NonInferiorityResult::Pass,
        }
    }

    #[test]
    fn strong_reproducible_effect_authorizes_capsule() {
        let result = run(valid());
        assert_eq!(result.verdict, TrialVerdict::Pass);
        assert!(result.capsule.unwrap().claim_authorized);
    }

    #[test]
    fn missing_matrix_fails_claim_without_hiding_result() {
        let mut input = valid();
        input.matrix_complete = false;
        let result = run(input);
        assert_eq!(result.verdict, TrialVerdict::Fail);
        assert!(result.capsule.is_some());
    }

    #[test]
    fn empty_samples_are_inconclusive() {
        let mut input = valid();
        input.paired_differences.clear();
        assert!(matches!(run(input).verdict, TrialVerdict::Inconclusive(_)));
    }
}
