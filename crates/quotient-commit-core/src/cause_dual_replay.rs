//! Conservative agreement rule for two independent causal replay engines.

use crate::{
    cause_replay::CausalReplayOutcome,
    cause_verdict::{CausalInconclusiveReason, CausalityVerdict},
};

pub fn compare(left: CausalReplayOutcome, right: CausalReplayOutcome) -> CausalReplayOutcome {
    if left == right {
        left
    } else {
        CausalReplayOutcome::Inconclusive(CausalInconclusiveReason::ReplayDisagreement)
    }
}

pub fn verdict(outcome: CausalReplayOutcome) -> CausalityVerdict {
    match outcome {
        CausalReplayOutcome::Causal { cause_size, .. } => CausalityVerdict::Causal {
            cause_size,
            contingency_size: 0,
        },
        CausalReplayOutcome::NonCausal {
            examined_interventions,
        } => CausalityVerdict::NonCausal {
            examined_interventions,
        },
        CausalReplayOutcome::Invalid(reason) => CausalityVerdict::Invalid(reason),
        CausalReplayOutcome::Inconclusive(reason) => CausalityVerdict::Inconclusive(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_causal_results_remain_causal() {
        let result = CausalReplayOutcome::Causal {
            witness_digest: [1; 32],
            cause_size: 2,
        };
        assert!(verdict(compare(result, result)).is_certified_causal());
    }

    #[test]
    fn digest_disagreement_is_inconclusive() {
        let left = CausalReplayOutcome::Causal {
            witness_digest: [1; 32],
            cause_size: 1,
        };
        let right = CausalReplayOutcome::Causal {
            witness_digest: [2; 32],
            cause_size: 1,
        };
        assert_eq!(
            verdict(compare(left, right)),
            CausalityVerdict::Inconclusive(CausalInconclusiveReason::ReplayDisagreement)
        );
    }

    #[test]
    fn terminal_class_disagreement_is_inconclusive() {
        let left = CausalReplayOutcome::NonCausal {
            examined_interventions: 3,
        };
        let right = CausalReplayOutcome::Inconclusive(CausalInconclusiveReason::NodeLimit);
        assert_eq!(
            compare(left, right),
            CausalReplayOutcome::Inconclusive(CausalInconclusiveReason::ReplayDisagreement)
        );
    }
}
