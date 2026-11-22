//! Operational cost from quarantine through certified rollback.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackCostMetric {
    pub quarantine_slots: u32,
    pub lost_actions: u32,
    pub rollback_latency_nanos: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackCostError {
    ZeroLatency,
    LostActionsExceedQuarantine,
}

impl RollbackCostMetric {
    pub fn new(
        quarantine_slots: u32,
        lost_actions: u32,
        rollback_latency_nanos: u64,
    ) -> Result<Self, RollbackCostError> {
        if rollback_latency_nanos == 0 {
            return Err(RollbackCostError::ZeroLatency);
        }
        if lost_actions > quarantine_slots {
            return Err(RollbackCostError::LostActionsExceedQuarantine);
        }
        Ok(Self {
            quarantine_slots,
            lost_actions,
            rollback_latency_nanos,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn impossible_lost_action_count_is_rejected() {
        assert_eq!(
            RollbackCostMetric::new(2, 3, 1),
            Err(RollbackCostError::LostActionsExceedQuarantine)
        );
    }
}
