//! Agreement rules for two independent replay engines.

use crate::{
    oracle_replay::ReplayOutcome,
    oracle_trace_step::TraceStep,
    oracle_verdict::{InconclusiveReason, InvalidReason, OracleVerdict},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayAgreement {
    ConfirmedCounterexample(TraceStep),
    NoCounterexampleObserved,
    Inconclusive(InconclusiveReason),
}

pub fn compare(left: ReplayOutcome, right: ReplayOutcome) -> ReplayAgreement {
    match (left, right) {
        (ReplayOutcome::FirstDifference(a), ReplayOutcome::FirstDifference(b)) if a == b => {
            ReplayAgreement::ConfirmedCounterexample(a)
        }
        (ReplayOutcome::NoDifference, ReplayOutcome::NoDifference) => {
            ReplayAgreement::NoCounterexampleObserved
        }
        (ReplayOutcome::Inconclusive(a), ReplayOutcome::Inconclusive(b)) if a == b => {
            ReplayAgreement::Inconclusive(a)
        }
        _ => ReplayAgreement::Inconclusive(InconclusiveReason::ReplayDisagreement),
    }
}

/// Maps replay agreement to a conservative oracle verdict.
///
/// Replay alone never establishes `Verified`.
pub fn verdict(agreement: ReplayAgreement) -> OracleVerdict {
    match agreement {
        ReplayAgreement::ConfirmedCounterexample(_) => {
            OracleVerdict::Invalid(InvalidReason::Counterexample)
        }
        ReplayAgreement::NoCounterexampleObserved => {
            OracleVerdict::Inconclusive(InconclusiveReason::Unsupported)
        }
        ReplayAgreement::Inconclusive(reason) => OracleVerdict::Inconclusive(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::StatePair;

    fn step(input: u16) -> TraceStep {
        TraceStep {
            slot: 1,
            input,
            before: StatePair {
                slot: 1,
                left: vec![1],
                right: vec![1],
            },
            after: StatePair {
                slot: 2,
                left: vec![2],
                right: vec![3],
            },
        }
    }

    #[test]
    fn matching_counterexample_is_invalid() {
        let agreement = compare(
            ReplayOutcome::FirstDifference(step(7)),
            ReplayOutcome::FirstDifference(step(7)),
        );
        assert_eq!(
            verdict(agreement),
            OracleVerdict::Invalid(InvalidReason::Counterexample)
        );
    }

    #[test]
    fn no_difference_does_not_promote_to_verified() {
        let result = verdict(compare(
            ReplayOutcome::NoDifference,
            ReplayOutcome::NoDifference,
        ));
        assert!(matches!(result, OracleVerdict::Inconclusive(_)));
    }

    #[test]
    fn disagreement_is_inconclusive() {
        let result = verdict(compare(
            ReplayOutcome::FirstDifference(step(7)),
            ReplayOutcome::FirstDifference(step(8)),
        ));
        assert_eq!(
            result,
            OracleVerdict::Inconclusive(InconclusiveReason::ReplayDisagreement)
        );
    }
}
