//! Fail-closed runtime assurance verdicts.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceInvalid {
    MalformedObservation,
    DeploymentMismatch,
    StaleEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceInconclusive {
    SampleLimit,
    WindowLimit,
    EvidenceGap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceVerdict {
    Healthy,
    Violated,
    Invalid(AssuranceInvalid),
    Inconclusive(AssuranceInconclusive),
}

impl AssuranceVerdict {
    #[must_use]
    pub const fn permit_remains_valid(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_healthy_preserves_the_permit() {
        assert!(AssuranceVerdict::Healthy.permit_remains_valid());
        for verdict in [
            AssuranceVerdict::Violated,
            AssuranceVerdict::Invalid(AssuranceInvalid::MalformedObservation),
            AssuranceVerdict::Inconclusive(AssuranceInconclusive::EvidenceGap),
        ] {
            assert!(!verdict.permit_remains_valid());
        }
    }
}
