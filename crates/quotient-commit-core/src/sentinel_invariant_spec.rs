//! Versioned runtime invariants for a certified repair.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeInvariantSpec {
    pub expected_action_digest: [u8; 32],
    pub forbidden_failure_code: u16,
    pub progress_bound_slots: u32,
    pub maximum_private_distinctions: u32,
    pub support_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvariantSpecError {
    ZeroDigest,
    ZeroFailureCode,
    ZeroProgressBound,
}

impl RuntimeInvariantSpec {
    pub fn new(
        expected_action_digest: [u8; 32],
        forbidden_failure_code: u16,
        progress_bound_slots: u32,
        maximum_private_distinctions: u32,
        support_digest: [u8; 32],
    ) -> Result<Self, InvariantSpecError> {
        if expected_action_digest == [0; 32] || support_digest == [0; 32] {
            return Err(InvariantSpecError::ZeroDigest);
        }
        if forbidden_failure_code == 0 {
            return Err(InvariantSpecError::ZeroFailureCode);
        }
        if progress_bound_slots == 0 {
            return Err(InvariantSpecError::ZeroProgressBound);
        }
        Ok(Self {
            expected_action_digest,
            forbidden_failure_code,
            progress_bound_slots,
            maximum_private_distinctions,
            support_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbounded_progress_is_rejected() {
        assert_eq!(
            RuntimeInvariantSpec::new([1; 32], 2, 0, 0, [3; 32]),
            Err(InvariantSpecError::ZeroProgressBound)
        );
    }
}
