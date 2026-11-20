//! Independent check that a repair preserves permitted action semantics.

use crate::remedy_action_semantics::{ProtectedActionSemantics, SemanticsError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionEquivalenceEvidence {
    pub baseline: ProtectedActionSemantics,
    pub repaired: ProtectedActionSemantics,
    pub baseline_trace_digest: [u8; 32],
    pub repaired_trace_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionEquivalenceError {
    ZeroTraceDigest,
    Semantics(SemanticsError),
}

pub fn verify(evidence: ActionEquivalenceEvidence) -> Result<(), ActionEquivalenceError> {
    if evidence.baseline_trace_digest == [0; 32] || evidence.repaired_trace_digest == [0; 32] {
        return Err(ActionEquivalenceError::ZeroTraceDigest);
    }
    evidence
        .baseline
        .verify_preserved(evidence.repaired)
        .map_err(ActionEquivalenceError::Semantics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_semantics_allow_different_trace_commitments() {
        let semantics = ProtectedActionSemantics::new([1; 32], [2; 32]).unwrap();
        assert_eq!(
            verify(ActionEquivalenceEvidence {
                baseline: semantics,
                repaired: semantics,
                baseline_trace_digest: [3; 32],
                repaired_trace_digest: [4; 32],
            }),
            Ok(())
        );
    }

    #[test]
    fn missing_trace_binding_fails_closed() {
        let semantics = ProtectedActionSemantics::new([1; 32], [2; 32]).unwrap();
        assert_eq!(
            verify(ActionEquivalenceEvidence {
                baseline: semantics,
                repaired: semantics,
                baseline_trace_digest: [0; 32],
                repaired_trace_digest: [4; 32],
            }),
            Err(ActionEquivalenceError::ZeroTraceDigest)
        );
    }
}
