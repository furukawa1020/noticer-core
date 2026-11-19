//! Stable taxonomy for independent causal replay disagreement.

use crate::{cause_replay::CausalReplayOutcome, cause_verdict::CausalInconclusiveReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDisagreement {
    None,
    TerminalClass,
    WitnessDigest,
    CauseSize,
    ExplorationCount,
    Reason,
}

impl ReplayDisagreement {
    pub fn code(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TerminalClass => "terminal-class",
            Self::WitnessDigest => "witness-digest",
            Self::CauseSize => "cause-size",
            Self::ExplorationCount => "exploration-count",
            Self::Reason => "reason",
        }
    }

    pub fn verdict_reason(self) -> Option<CausalInconclusiveReason> {
        (self != Self::None).then_some(CausalInconclusiveReason::ReplayDisagreement)
    }
}

pub fn classify(left: CausalReplayOutcome, right: CausalReplayOutcome) -> ReplayDisagreement {
    match (left, right) {
        (
            CausalReplayOutcome::Causal {
                witness_digest: a,
                cause_size: x,
            },
            CausalReplayOutcome::Causal {
                witness_digest: b,
                cause_size: y,
            },
        ) => {
            if a != b {
                ReplayDisagreement::WitnessDigest
            } else if x != y {
                ReplayDisagreement::CauseSize
            } else {
                ReplayDisagreement::None
            }
        }
        (
            CausalReplayOutcome::NonCausal {
                examined_interventions: a,
            },
            CausalReplayOutcome::NonCausal {
                examined_interventions: b,
            },
        ) => {
            if a == b {
                ReplayDisagreement::None
            } else {
                ReplayDisagreement::ExplorationCount
            }
        }
        (CausalReplayOutcome::Invalid(a), CausalReplayOutcome::Invalid(b)) => {
            if a == b {
                ReplayDisagreement::None
            } else {
                ReplayDisagreement::Reason
            }
        }
        (CausalReplayOutcome::Inconclusive(a), CausalReplayOutcome::Inconclusive(b)) => {
            if a == b {
                ReplayDisagreement::None
            } else {
                ReplayDisagreement::Reason
            }
        }
        _ => ReplayDisagreement::TerminalClass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_difference_has_stable_code() {
        let left = CausalReplayOutcome::Causal {
            witness_digest: [1; 32],
            cause_size: 1,
        };
        let right = CausalReplayOutcome::Causal {
            witness_digest: [2; 32],
            cause_size: 1,
        };
        let result = classify(left, right);
        assert_eq!(result, ReplayDisagreement::WitnessDigest);
        assert_eq!(result.code(), "witness-digest");
        assert_eq!(
            result.verdict_reason(),
            Some(CausalInconclusiveReason::ReplayDisagreement)
        );
    }

    #[test]
    fn matching_results_have_no_disagreement() {
        let result = CausalReplayOutcome::NonCausal {
            examined_interventions: 4,
        };
        assert_eq!(classify(result, result), ReplayDisagreement::None);
    }
}
