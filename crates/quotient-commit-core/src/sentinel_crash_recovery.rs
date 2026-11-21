//! Fail-closed restoration of runtime assurance state.

use crate::sentinel_checkpoint::AssuranceCheckpoint;
use crate::sentinel_verdict::{AssuranceInconclusive, AssuranceInvalid, AssuranceVerdict};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredAssuranceState {
    pub checkpoint: AssuranceCheckpoint,
    pub verdict: AssuranceVerdict,
}

pub fn recover(
    checkpoint: Option<AssuranceCheckpoint>,
    expected_digest: [u8; 32],
) -> RecoveredAssuranceState {
    let Some(checkpoint) = checkpoint else {
        return RecoveredAssuranceState {
            checkpoint: AssuranceCheckpoint {
                deployment_identity_digest: [0; 32],
                monitor_state_digest: [0; 32],
                window_frontier_digest: [0; 32],
                budget_digest: [0; 32],
                last_sequence: 0,
            },
            verdict: AssuranceVerdict::Inconclusive(AssuranceInconclusive::EvidenceGap),
        };
    };
    let verdict = if checkpoint.digest() == expected_digest {
        AssuranceVerdict::Healthy
    } else {
        AssuranceVerdict::Invalid(AssuranceInvalid::StaleEvidence)
    };
    RecoveredAssuranceState {
        checkpoint,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_checkpoint_never_recovers_as_healthy() {
        assert!(matches!(
            recover(None, [1; 32]).verdict,
            AssuranceVerdict::Inconclusive(AssuranceInconclusive::EvidenceGap)
        ));
    }

    #[test]
    fn authenticated_checkpoint_recovers() {
        let checkpoint = AssuranceCheckpoint::new([1; 32], [2; 32], [3; 32], [4; 32], 5).unwrap();
        assert_eq!(
            recover(Some(checkpoint), checkpoint.digest()).verdict,
            AssuranceVerdict::Healthy
        );
    }
}
