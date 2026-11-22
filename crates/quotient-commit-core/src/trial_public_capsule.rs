//! Public-safe comparison with uncertainty and explicit claim boundary.

use crate::trial_verdict::TrialVerdict;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicTrialCapsule {
    pub verdict: TrialVerdict,
    pub comparison_label: String,
    pub estimate: i64,
    pub lower_bound: i64,
    pub upper_bound: i64,
    pub unit: String,
    pub manifest_digest: [u8; 32],
    pub claim_authorized: bool,
    pub censoring_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicTrialCapsuleInput {
    pub verdict: TrialVerdict,
    pub comparison_label: String,
    pub estimate: i64,
    pub lower_bound: i64,
    pub upper_bound: i64,
    pub unit: String,
    pub manifest_digest: [u8; 32],
    pub claim_authorized: bool,
    pub censoring_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrialCapsuleError {
    UnsafeLabel,
    InvalidInterval,
    ZeroManifest,
    UnauthorizedPass,
}

impl PublicTrialCapsule {
    pub fn new(input: PublicTrialCapsuleInput) -> Result<Self, TrialCapsuleError> {
        if input.comparison_label.is_empty()
            || input.unit.is_empty()
            || !input.comparison_label.is_ascii()
            || !input.unit.is_ascii()
            || input.comparison_label.contains(['=', ':'])
        {
            return Err(TrialCapsuleError::UnsafeLabel);
        }
        if input.lower_bound > input.estimate || input.estimate > input.upper_bound {
            return Err(TrialCapsuleError::InvalidInterval);
        }
        if input.manifest_digest == [0; 32] {
            return Err(TrialCapsuleError::ZeroManifest);
        }
        if input.verdict.supports_claim() && !input.claim_authorized {
            return Err(TrialCapsuleError::UnauthorizedPass);
        }
        Ok(Self {
            verdict: input.verdict,
            comparison_label: input.comparison_label,
            estimate: input.estimate,
            lower_bound: input.lower_bound,
            upper_bound: input.upper_bound,
            unit: input.unit,
            manifest_digest: input.manifest_digest,
            claim_authorized: input.claim_authorized,
            censoring_count: input.censoring_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_without_claim_evidence_is_rejected() {
        assert_eq!(
            PublicTrialCapsule::new(PublicTrialCapsuleInput {
                verdict: TrialVerdict::Pass,
                comparison_label: "latency".into(),
                estimate: 1,
                lower_bound: 0,
                upper_bound: 2,
                unit: "ns".into(),
                manifest_digest: [1; 32],
                claim_authorized: false,
                censoring_count: 0,
            }),
            Err(TrialCapsuleError::UnauthorizedPass)
        );
    }
}
