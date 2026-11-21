//! Durable commitment to the runtime assurance frontier.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceCheckpoint {
    pub deployment_identity_digest: [u8; 32],
    pub monitor_state_digest: [u8; 32],
    pub window_frontier_digest: [u8; 32],
    pub budget_digest: [u8; 32],
    pub last_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    ZeroBinding,
    ZeroSequence,
}

impl AssuranceCheckpoint {
    pub fn new(
        deployment_identity_digest: [u8; 32],
        monitor_state_digest: [u8; 32],
        window_frontier_digest: [u8; 32],
        budget_digest: [u8; 32],
        last_sequence: u64,
    ) -> Result<Self, CheckpointError> {
        if [
            deployment_identity_digest,
            monitor_state_digest,
            window_frontier_digest,
            budget_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(CheckpointError::ZeroBinding);
        }
        if last_sequence == 0 {
            return Err(CheckpointError::ZeroSequence);
        }
        Ok(Self {
            deployment_identity_digest,
            monitor_state_digest,
            window_frontier_digest,
            budget_digest,
            last_sequence,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-sentinel.checkpoint.v1\0".to_vec();
        for digest in [
            self.deployment_identity_digest,
            self.monitor_state_digest,
            self.window_frontier_digest,
            self.budget_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.last_sequence.to_be_bytes());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontier_and_budget_are_committed() {
        let a = AssuranceCheckpoint::new([1; 32], [2; 32], [3; 32], [4; 32], 5).unwrap();
        let b = AssuranceCheckpoint::new([1; 32], [2; 32], [3; 32], [9; 32], 5).unwrap();
        assert_ne!(a.digest(), b.digest());
    }
}
