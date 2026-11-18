//! Four-way verdict for bounded counterfactual causality analysis.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalInvalidReason {
    Parse,
    Domain,
    NonCanonical,
    ActualWorldMismatch,
    WitnessRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalInconclusiveReason {
    NodeLimit,
    InterventionLimit,
    DepthLimit,
    UnsupportedEquation,
    ReplayDisagreement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalityVerdict {
    Causal {
        cause_size: u32,
        contingency_size: u32,
    },
    NonCausal {
        examined_interventions: u64,
    },
    Invalid(CausalInvalidReason),
    Inconclusive(CausalInconclusiveReason),
}

impl CausalityVerdict {
    pub fn is_certified_causal(self) -> bool {
        matches!(self, Self::Causal { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_terminal_classes_remain_distinct() {
        let causal = CausalityVerdict::Causal {
            cause_size: 1,
            contingency_size: 0,
        };
        let non_causal = CausalityVerdict::NonCausal {
            examined_interventions: 8,
        };
        let invalid = CausalityVerdict::Invalid(CausalInvalidReason::Domain);
        let inconclusive = CausalityVerdict::Inconclusive(CausalInconclusiveReason::NodeLimit);
        assert!(causal.is_certified_causal());
        assert!(!non_causal.is_certified_causal());
        assert!(!invalid.is_certified_causal());
        assert!(!inconclusive.is_certified_causal());
        assert_ne!(invalid, inconclusive);
    }

    #[test]
    fn resource_exhaustion_is_not_non_causal() {
        assert_ne!(
            CausalityVerdict::Inconclusive(CausalInconclusiveReason::InterventionLimit),
            CausalityVerdict::NonCausal {
                examined_interventions: 0
            }
        );
    }
}
