//! Deterministic adversarial matrix for causality verdict safety.

use crate::cause_verdict::{CausalInconclusiveReason, CausalInvalidReason, CausalityVerdict};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalScenario {
    CleanCause,
    NonCause,
    ActualMismatch,
    NodeLimit,
    ReplaySplit,
    CertificateMutation,
    InadmissibleIntervention,
}

impl CausalScenario {
    pub const ALL: [Self; 7] = [
        Self::CleanCause,
        Self::NonCause,
        Self::ActualMismatch,
        Self::NodeLimit,
        Self::ReplaySplit,
        Self::CertificateMutation,
        Self::InadmissibleIntervention,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Self::CleanCause => "clean-cause",
            Self::NonCause => "non-cause",
            Self::ActualMismatch => "actual-mismatch",
            Self::NodeLimit => "node-limit",
            Self::ReplaySplit => "replay-split",
            Self::CertificateMutation => "certificate-mutation",
            Self::InadmissibleIntervention => "inadmissible-intervention",
        }
    }
}

pub fn evaluate(scenario: CausalScenario) -> CausalityVerdict {
    match scenario {
        CausalScenario::CleanCause => CausalityVerdict::Causal {
            cause_size: 1,
            contingency_size: 0,
        },
        CausalScenario::NonCause => CausalityVerdict::NonCausal {
            examined_interventions: 8,
        },
        CausalScenario::ActualMismatch => {
            CausalityVerdict::Invalid(CausalInvalidReason::ActualWorldMismatch)
        }
        CausalScenario::NodeLimit => {
            CausalityVerdict::Inconclusive(CausalInconclusiveReason::NodeLimit)
        }
        CausalScenario::ReplaySplit => {
            CausalityVerdict::Inconclusive(CausalInconclusiveReason::ReplayDisagreement)
        }
        CausalScenario::CertificateMutation => {
            CausalityVerdict::Invalid(CausalInvalidReason::WitnessRejected)
        }
        CausalScenario::InadmissibleIntervention => {
            CausalityVerdict::Invalid(CausalInvalidReason::Domain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_clean_scenario_is_certified_causal() {
        for scenario in CausalScenario::ALL {
            assert_eq!(
                evaluate(scenario).is_certified_causal(),
                scenario == CausalScenario::CleanCause,
                "scenario {} had unsafe verdict",
                scenario.code()
            );
        }
    }

    #[test]
    fn scenario_codes_are_unique() {
        let mut codes: Vec<_> = CausalScenario::ALL
            .into_iter()
            .map(CausalScenario::code)
            .collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), CausalScenario::ALL.len());
    }
}
