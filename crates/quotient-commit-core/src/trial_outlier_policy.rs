//! Pre-registered exclusion reasons; numeric surprise is not an exclusion reason.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExclusionReason {
    HarnessFailure,
    EnvironmentMismatch,
    ContractViolation,
    CorruptArtifact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutlierDecision {
    pub exclude: bool,
    pub reason: Option<ExclusionReason>,
    pub evidence_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutlierPolicyError {
    MissingReason,
    MissingEvidence,
    ReasonWithoutExclusion,
}

pub fn validate(decision: OutlierDecision) -> Result<(), OutlierPolicyError> {
    if decision.exclude && decision.reason.is_none() {
        return Err(OutlierPolicyError::MissingReason);
    }
    if decision.exclude && decision.evidence_digest == [0; 32] {
        return Err(OutlierPolicyError::MissingEvidence);
    }
    if !decision.exclude && decision.reason.is_some() {
        return Err(OutlierPolicyError::ReasonWithoutExclusion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exclusion_requires_auditable_evidence() {
        assert_eq!(
            validate(OutlierDecision {
                exclude: true,
                reason: Some(ExclusionReason::HarnessFailure),
                evidence_digest: [0; 32]
            }),
            Err(OutlierPolicyError::MissingEvidence)
        );
    }
}
