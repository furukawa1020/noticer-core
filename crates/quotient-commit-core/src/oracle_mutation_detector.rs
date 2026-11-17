//! Field-level mutation diagnostics for authenticated oracle artifacts.

use crate::{oracle_artifact::OracleArtifact, oracle_artifact_auth::AuthenticatedArtifact};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationReport {
    Clean,
    SchemaVersion,
    OracleVersion,
    Verdict,
    Trace,
    Exploration,
    ReplayDigests,
    Authentication,
}

pub fn inspect(
    key: [u8; 32],
    trusted: &OracleArtifact,
    candidate: &AuthenticatedArtifact,
) -> MutationReport {
    if candidate.verify(key) && &candidate.artifact == trusted {
        return MutationReport::Clean;
    }
    let artifact = &candidate.artifact;
    if artifact.schema_version != trusted.schema_version {
        MutationReport::SchemaVersion
    } else if artifact.oracle_version != trusted.oracle_version {
        MutationReport::OracleVersion
    } else if artifact.verdict != trusted.verdict {
        MutationReport::Verdict
    } else if artifact.trace != trusted.trace {
        MutationReport::Trace
    } else if artifact.exploration != trusted.exploration {
        MutationReport::Exploration
    } else if artifact.replay_digests != trusted.replay_digests {
        MutationReport::ReplayDigests
    } else {
        MutationReport::Authentication
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        oracle_artifact::ExplorationRecord,
        oracle_state_pair::StatePair,
        oracle_trace_step::TraceStep,
        oracle_verdict::{InvalidReason, OracleVerdict},
    };

    fn artifact() -> OracleArtifact {
        OracleArtifact::new(
            2,
            OracleVerdict::Invalid(InvalidReason::Counterexample),
            vec![TraceStep {
                slot: 1,
                input: 4,
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
            }],
            ExplorationRecord {
                explored_nodes: 4,
                explored_transitions: 7,
                maximum_depth: 1,
            },
            [[5; 32], [5; 32]],
        )
        .unwrap()
    }

    #[test]
    fn unchanged_envelope_is_clean() {
        let trusted = artifact();
        let envelope = AuthenticatedArtifact::issue([8; 32], trusted.clone()).unwrap();
        assert_eq!(inspect([8; 32], &trusted, &envelope), MutationReport::Clean);
    }

    #[test]
    fn trace_mutation_is_located() {
        let trusted = artifact();
        let mut envelope = AuthenticatedArtifact::issue([8; 32], trusted.clone()).unwrap();
        envelope.artifact.trace[0].input = 9;
        assert_eq!(inspect([8; 32], &trusted, &envelope), MutationReport::Trace);
    }

    #[test]
    fn verdict_mutation_is_located_before_trace_validation() {
        let trusted = artifact();
        let mut envelope = AuthenticatedArtifact::issue([8; 32], trusted.clone()).unwrap();
        envelope.artifact.verdict = OracleVerdict::Verified { explored: 4 };
        assert_eq!(
            inspect([8; 32], &trusted, &envelope),
            MutationReport::Verdict
        );
    }

    #[test]
    fn exploration_and_replay_mutations_are_distinct() {
        let trusted = artifact();
        let mut limits = AuthenticatedArtifact::issue([8; 32], trusted.clone()).unwrap();
        limits.artifact.exploration.maximum_depth += 1;
        assert_eq!(
            inspect([8; 32], &trusted, &limits),
            MutationReport::Exploration
        );

        let mut replay = AuthenticatedArtifact::issue([8; 32], trusted.clone()).unwrap();
        replay.artifact.replay_digests[1][0] ^= 1;
        assert_eq!(
            inspect([8; 32], &trusted, &replay),
            MutationReport::ReplayDigests
        );
    }
}
