//! Canonical artifact schema for minimal counterexample oracle results.

use crate::{
    oracle_trace_step::TraceStep,
    oracle_verdict::{InconclusiveReason, InvalidReason, OracleVerdict},
};

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExplorationRecord {
    pub explored_nodes: u64,
    pub explored_transitions: u64,
    pub maximum_depth: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleArtifact {
    pub schema_version: u16,
    pub oracle_version: u32,
    pub verdict: OracleVerdict,
    pub trace: Vec<TraceStep>,
    pub exploration: ExplorationRecord,
    pub replay_digests: [[u8; 32]; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    UnsupportedSchema,
    CounterexampleTraceMissing,
    NonCounterexampleHasTrace,
}

impl OracleArtifact {
    pub fn new(
        oracle_version: u32,
        verdict: OracleVerdict,
        trace: Vec<TraceStep>,
        exploration: ExplorationRecord,
        replay_digests: [[u8; 32]; 2],
    ) -> Result<Self, ArtifactError> {
        let artifact = Self {
            schema_version: SCHEMA_VERSION,
            oracle_version,
            verdict,
            trace,
            exploration,
            replay_digests,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ArtifactError::UnsupportedSchema);
        }
        match self.verdict {
            OracleVerdict::Invalid(InvalidReason::Counterexample) if self.trace.is_empty() => {
                Err(ArtifactError::CounterexampleTraceMissing)
            }
            OracleVerdict::Invalid(InvalidReason::Counterexample) => Ok(()),
            _ if !self.trace.is_empty() => Err(ArtifactError::NonCounterexampleHasTrace),
            _ => Ok(()),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"noticer.oracle.artifact.v1\0".to_vec();
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(&self.oracle_version.to_be_bytes());
        encode_verdict(&self.verdict, &mut out);
        out.extend_from_slice(&(self.trace.len() as u64).to_be_bytes());
        for step in &self.trace {
            encode_step(step, &mut out);
        }
        out.extend_from_slice(&self.exploration.explored_nodes.to_be_bytes());
        out.extend_from_slice(&self.exploration.explored_transitions.to_be_bytes());
        out.extend_from_slice(&self.exploration.maximum_depth.to_be_bytes());
        out.extend_from_slice(&self.replay_digests[0]);
        out.extend_from_slice(&self.replay_digests[1]);
        out
    }
}

fn encode_verdict(verdict: &OracleVerdict, out: &mut Vec<u8>) {
    match verdict {
        OracleVerdict::Verified { explored } => {
            out.push(0);
            out.extend_from_slice(&explored.to_be_bytes());
        }
        OracleVerdict::Invalid(reason) => {
            out.push(1);
            out.push(match reason {
                InvalidReason::Parse => 0,
                InvalidReason::Domain => 1,
                InvalidReason::NonCanonical => 2,
                InvalidReason::Counterexample => 3,
            });
        }
        OracleVerdict::Inconclusive(reason) => {
            out.push(2);
            out.push(match reason {
                InconclusiveReason::NodeLimit => 0,
                InconclusiveReason::TransitionLimit => 1,
                InconclusiveReason::DepthLimit => 2,
                InconclusiveReason::Unsupported => 3,
                InconclusiveReason::ReplayDisagreement => 4,
            });
        }
    }
}

fn encode_step(step: &TraceStep, out: &mut Vec<u8>) {
    out.extend_from_slice(&step.slot.to_be_bytes());
    out.extend_from_slice(&step.input.to_be_bytes());
    for state in [&step.before, &step.after] {
        out.extend_from_slice(&state.slot.to_be_bytes());
        out.extend_from_slice(&(state.left.len() as u64).to_be_bytes());
        out.extend_from_slice(&state.left);
        out.extend_from_slice(&(state.right.len() as u64).to_be_bytes());
        out.extend_from_slice(&state.right);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::StatePair;

    fn step() -> TraceStep {
        TraceStep {
            slot: 4,
            input: 7,
            before: StatePair {
                slot: 4,
                left: vec![1],
                right: vec![1],
            },
            after: StatePair {
                slot: 5,
                left: vec![2],
                right: vec![3],
            },
        }
    }

    fn exploration() -> ExplorationRecord {
        ExplorationRecord {
            explored_nodes: 8,
            explored_transitions: 12,
            maximum_depth: 4,
        }
    }

    #[test]
    fn counterexample_requires_complete_trace() {
        assert_eq!(
            OracleArtifact::new(
                1,
                OracleVerdict::Invalid(InvalidReason::Counterexample),
                vec![],
                exploration(),
                [[1; 32], [2; 32]]
            ),
            Err(ArtifactError::CounterexampleTraceMissing)
        );
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let artifact = OracleArtifact::new(
            1,
            OracleVerdict::Invalid(InvalidReason::Counterexample),
            vec![step()],
            exploration(),
            [[1; 32], [2; 32]],
        )
        .unwrap();
        assert_eq!(artifact.canonical_bytes(), artifact.canonical_bytes());
    }

    #[test]
    fn inconclusive_cannot_carry_counterexample_trace() {
        assert_eq!(
            OracleArtifact::new(
                1,
                OracleVerdict::Inconclusive(InconclusiveReason::NodeLimit),
                vec![step()],
                exploration(),
                [[1; 32], [2; 32]]
            ),
            Err(ArtifactError::NonCounterexampleHasTrace)
        );
    }
}
