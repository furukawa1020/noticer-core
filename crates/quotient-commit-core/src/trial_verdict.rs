//! Fail-closed verdicts for comparative experiments.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidTrial {
    ContractMismatch,
    MalformedSample,
    UnauthenticatedArtifact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InconclusiveTrial {
    Timeout,
    ResourceLimit,
    InsufficientRepetitions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrialVerdict {
    Pass,
    Fail,
    Invalid(InvalidTrial),
    Inconclusive(InconclusiveTrial),
}

impl TrialVerdict {
    #[must_use]
    pub const fn supports_claim(self) -> bool {
        matches!(self, Self::Pass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pass_supports_a_claim() {
        assert!(TrialVerdict::Pass.supports_claim());
        assert!(!TrialVerdict::Fail.supports_claim());
        assert!(!TrialVerdict::Invalid(InvalidTrial::MalformedSample).supports_claim());
        assert!(!TrialVerdict::Inconclusive(InconclusiveTrial::Timeout).supports_claim());
    }
}
