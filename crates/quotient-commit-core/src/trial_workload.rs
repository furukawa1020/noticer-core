//! Dataset-independent workload contract for paired evaluation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadContract {
    pub distribution_digest: [u8; 32],
    pub action_classes: u16,
    pub private_history_classes: u16,
    pub slots: u32,
    pub observer_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadError {
    ZeroDigest,
    EmptyClass,
    TooFewSlots,
}

impl WorkloadContract {
    pub fn new(
        distribution_digest: [u8; 32],
        action_classes: u16,
        private_history_classes: u16,
        slots: u32,
        observer_digest: [u8; 32],
    ) -> Result<Self, WorkloadError> {
        if distribution_digest == [0; 32] || observer_digest == [0; 32] {
            return Err(WorkloadError::ZeroDigest);
        }
        if action_classes == 0 || private_history_classes == 0 {
            return Err(WorkloadError::EmptyClass);
        }
        if slots < 2 {
            return Err(WorkloadError::TooFewSlots);
        }
        Ok(Self {
            distribution_digest,
            action_classes,
            private_history_classes,
            slots,
            observer_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn degenerate_workload_is_rejected() {
        assert_eq!(
            WorkloadContract::new([1; 32], 1, 1, 1, [2; 32]),
            Err(WorkloadError::TooFewSlots)
        );
    }
}
