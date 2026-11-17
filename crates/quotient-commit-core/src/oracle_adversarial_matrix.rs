//! Deterministic adversarial scenario matrix for oracle verdict safety.

use crate::oracle_verdict::{InconclusiveReason, InvalidReason, OracleVerdict};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdversarialScenario {
    Clean,
    InvalidInput,
    NodeLimit,
    DepthLimit,
    ReplayDisagreement,
    StateMutation,
}

impl AdversarialScenario {
    pub const ALL: [Self; 6] = [
        Self::Clean,
        Self::InvalidInput,
        Self::NodeLimit,
        Self::DepthLimit,
        Self::ReplayDisagreement,
        Self::StateMutation,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::InvalidInput => "invalid-input",
            Self::NodeLimit => "node-limit",
            Self::DepthLimit => "depth-limit",
            Self::ReplayDisagreement => "replay-disagreement",
            Self::StateMutation => "state-mutation",
        }
    }
}

pub fn evaluate(scenario: AdversarialScenario, explored: u64) -> OracleVerdict {
    match scenario {
        AdversarialScenario::Clean => OracleVerdict::Verified { explored },
        AdversarialScenario::InvalidInput => OracleVerdict::Invalid(InvalidReason::Domain),
        AdversarialScenario::NodeLimit => {
            OracleVerdict::Inconclusive(InconclusiveReason::NodeLimit)
        }
        AdversarialScenario::DepthLimit => {
            OracleVerdict::Inconclusive(InconclusiveReason::DepthLimit)
        }
        AdversarialScenario::ReplayDisagreement => {
            OracleVerdict::Inconclusive(InconclusiveReason::ReplayDisagreement)
        }
        AdversarialScenario::StateMutation => OracleVerdict::Invalid(InvalidReason::NonCanonical),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_promotion_gate::{PromotionError, PromotionGate};

    #[test]
    fn only_clean_scenario_is_verified() {
        for scenario in AdversarialScenario::ALL {
            let verdict = evaluate(scenario, 21);
            assert_eq!(
                matches!(verdict, OracleVerdict::Verified { .. }),
                scenario == AdversarialScenario::Clean,
                "scenario {} had unexpected verdict",
                scenario.code()
            );
        }
    }

    #[test]
    fn every_abnormal_scenario_is_rejected_by_promotion_gate() {
        for scenario in AdversarialScenario::ALL
            .into_iter()
            .filter(|scenario| *scenario != AdversarialScenario::Clean)
        {
            let result = PromotionGate::new(evaluate(scenario, 21)).confirm(true);
            assert!(
                matches!(
                    result,
                    Err(PromotionError::InvalidCannotVerify)
                        | Err(PromotionError::InconclusiveCannotVerify)
                ),
                "scenario {} was promoted",
                scenario.code()
            );
        }
    }

    #[test]
    fn scenario_codes_are_unique() {
        let mut codes: Vec<_> = AdversarialScenario::ALL
            .into_iter()
            .map(AdversarialScenario::code)
            .collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), AdversarialScenario::ALL.len());
    }
}
