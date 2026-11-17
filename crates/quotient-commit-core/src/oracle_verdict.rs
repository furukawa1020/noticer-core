#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidReason {
    Parse,
    Domain,
    NonCanonical,
    Counterexample,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InconclusiveReason {
    NodeLimit,
    TransitionLimit,
    DepthLimit,
    Unsupported,
    ReplayDisagreement,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleVerdict {
    Verified { explored: u64 },
    Invalid(InvalidReason),
    Inconclusive(InconclusiveReason),
}
impl OracleVerdict {
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified { .. })
    }
    pub fn explored(self) -> Option<u64> {
        if let Self::Verified { explored } = self {
            Some(explored)
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_verified_has_success_payload() {
        assert_eq!(OracleVerdict::Verified { explored: 3 }.explored(), Some(3));
        assert_eq!(
            OracleVerdict::Invalid(InvalidReason::Parse).explored(),
            None
        );
        assert_eq!(
            OracleVerdict::Inconclusive(InconclusiveReason::NodeLimit).explored(),
            None
        )
    }
    #[test]
    fn variants_are_distinct() {
        assert!(!OracleVerdict::Invalid(InvalidReason::Domain).is_verified());
        assert!(!OracleVerdict::Inconclusive(InconclusiveReason::DepthLimit).is_verified());
    }
}
