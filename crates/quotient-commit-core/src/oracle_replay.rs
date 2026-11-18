//! Independent replay interface for counterexample traces.

use crate::{oracle_trace_step::TraceStep, oracle_verdict::InconclusiveReason};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayOutcome {
    FirstDifference(TraceStep),
    NoDifference,
    Inconclusive(InconclusiveReason),
}

/// An independently implemented engine that replays an oracle trace.
pub trait ReplayEngine {
    fn replay(&self, trace: &[TraceStep]) -> ReplayOutcome;
}

pub fn replay_with<E: ReplayEngine>(engine: &E, trace: &[TraceStep]) -> ReplayOutcome {
    engine.replay(trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::StatePair;

    struct FirstStepEngine;

    impl ReplayEngine for FirstStepEngine {
        fn replay(&self, trace: &[TraceStep]) -> ReplayOutcome {
            trace
                .first()
                .cloned()
                .map(ReplayOutcome::FirstDifference)
                .unwrap_or(ReplayOutcome::NoDifference)
        }
    }

    fn step() -> TraceStep {
        TraceStep {
            slot: 8,
            input: 1,
            before: StatePair {
                slot: 8,
                left: vec![2],
                right: vec![2],
            },
            after: StatePair {
                slot: 9,
                left: vec![3],
                right: vec![4],
            },
        }
    }

    #[test]
    fn first_difference_keeps_complete_trace_step() {
        let expected = step();
        assert_eq!(
            replay_with(&FirstStepEngine, std::slice::from_ref(&expected)),
            ReplayOutcome::FirstDifference(expected)
        );
    }

    #[test]
    fn empty_trace_has_no_difference() {
        assert_eq!(
            replay_with(&FirstStepEngine, &[]),
            ReplayOutcome::NoDifference
        );
    }
}
