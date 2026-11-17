//! Stable diagnostics for disagreement between independent replay engines.

use crate::{oracle_replay::ReplayOutcome, oracle_verdict::InconclusiveReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDisagreement {
    None,
    Termination,
    Slot,
    Input,
    BeforeState,
    AfterState,
    InconclusiveReason,
}

impl ReplayDisagreement {
    pub fn code(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Termination => "termination",
            Self::Slot => "slot",
            Self::Input => "input",
            Self::BeforeState => "before-state",
            Self::AfterState => "after-state",
            Self::InconclusiveReason => "inconclusive-reason",
        }
    }

    pub fn verdict_reason(self) -> Option<InconclusiveReason> {
        (self != Self::None).then_some(InconclusiveReason::ReplayDisagreement)
    }
}

pub fn classify(left: &ReplayOutcome, right: &ReplayOutcome) -> ReplayDisagreement {
    match (left, right) {
        (ReplayOutcome::NoDifference, ReplayOutcome::NoDifference) => ReplayDisagreement::None,
        (ReplayOutcome::Inconclusive(a), ReplayOutcome::Inconclusive(b)) => {
            if a == b {
                ReplayDisagreement::None
            } else {
                ReplayDisagreement::InconclusiveReason
            }
        }
        (ReplayOutcome::FirstDifference(a), ReplayOutcome::FirstDifference(b)) => {
            if a.slot != b.slot {
                ReplayDisagreement::Slot
            } else if a.input != b.input {
                ReplayDisagreement::Input
            } else if a.before != b.before {
                ReplayDisagreement::BeforeState
            } else if a.after != b.after {
                ReplayDisagreement::AfterState
            } else {
                ReplayDisagreement::None
            }
        }
        _ => ReplayDisagreement::Termination,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{oracle_state_pair::StatePair, oracle_trace_step::TraceStep};

    fn step(slot: u64, input: u16) -> TraceStep {
        TraceStep {
            slot,
            input,
            before: StatePair {
                slot,
                left: vec![1],
                right: vec![1],
            },
            after: StatePair {
                slot: slot + 1,
                left: vec![2],
                right: vec![3],
            },
        }
    }

    #[test]
    fn input_difference_has_stable_diagnostic() {
        let result = classify(
            &ReplayOutcome::FirstDifference(step(2, 7)),
            &ReplayOutcome::FirstDifference(step(2, 8)),
        );
        assert_eq!(result, ReplayDisagreement::Input);
        assert_eq!(result.code(), "input");
        assert_eq!(
            result.verdict_reason(),
            Some(InconclusiveReason::ReplayDisagreement)
        );
    }

    #[test]
    fn different_termination_is_inconclusive() {
        let result = classify(
            &ReplayOutcome::NoDifference,
            &ReplayOutcome::FirstDifference(step(2, 7)),
        );
        assert_eq!(result, ReplayDisagreement::Termination);
        assert!(result.verdict_reason().is_some());
    }
}
