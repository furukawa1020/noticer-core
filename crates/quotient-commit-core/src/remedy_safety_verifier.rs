//! Safety proof that the observed release failure disappears after repair.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyEvidence {
    pub failure_in_actual_world: bool,
    pub failure_in_repaired_world: bool,
    pub actual_world_digest: [u8; 32],
    pub repaired_world_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyError {
    ZeroWorldDigest,
    NoActualFailure,
    FailurePersists,
    SameWorld,
}

pub fn verify(evidence: SafetyEvidence) -> Result<(), SafetyError> {
    if evidence.actual_world_digest == [0; 32] || evidence.repaired_world_digest == [0; 32] {
        return Err(SafetyError::ZeroWorldDigest);
    }
    if evidence.actual_world_digest == evidence.repaired_world_digest {
        return Err(SafetyError::SameWorld);
    }
    if !evidence.failure_in_actual_world {
        return Err(SafetyError::NoActualFailure);
    }
    if evidence.failure_in_repaired_world {
        return Err(SafetyError::FailurePersists);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_disappearing_actual_failure_is_safe() {
        assert_eq!(
            verify(SafetyEvidence {
                failure_in_actual_world: true,
                failure_in_repaired_world: false,
                actual_world_digest: [1; 32],
                repaired_world_digest: [2; 32]
            }),
            Ok(())
        );
        assert_eq!(
            verify(SafetyEvidence {
                failure_in_actual_world: true,
                failure_in_repaired_world: true,
                actual_world_digest: [1; 32],
                repaired_world_digest: [2; 32]
            }),
            Err(SafetyError::FailurePersists)
        );
    }
}
