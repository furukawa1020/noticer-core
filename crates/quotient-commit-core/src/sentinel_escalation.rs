//! Deterministic response selected from alarm severity and evidence confidence.

use crate::sentinel_alarm_fusion::AlarmSeverity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceResponse {
    ContinueMonitoring,
    OperatorReview,
    Quarantine,
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceEscalationPolicy {
    rollback_confidence_ppm: u32,
}

impl AssuranceEscalationPolicy {
    pub fn new(rollback_confidence_ppm: u32) -> Option<Self> {
        (rollback_confidence_ppm <= 1_000_000).then_some(Self {
            rollback_confidence_ppm,
        })
    }

    #[must_use]
    pub const fn decide(self, severity: AlarmSeverity, confidence_ppm: u32) -> AssuranceResponse {
        match severity {
            AlarmSeverity::Notice => AssuranceResponse::ContinueMonitoring,
            AlarmSeverity::Elevated => AssuranceResponse::OperatorReview,
            AlarmSeverity::Critical if confidence_ppm >= self.rollback_confidence_ppm => {
                AssuranceResponse::Rollback
            }
            AlarmSeverity::Critical => AssuranceResponse::Quarantine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_critical_alarm_quarantines_before_rollback() {
        let policy = AssuranceEscalationPolicy::new(900_000).unwrap();
        assert_eq!(
            policy.decide(AlarmSeverity::Critical, 800_000),
            AssuranceResponse::Quarantine
        );
        assert_eq!(
            policy.decide(AlarmSeverity::Critical, 900_000),
            AssuranceResponse::Rollback
        );
    }
}
