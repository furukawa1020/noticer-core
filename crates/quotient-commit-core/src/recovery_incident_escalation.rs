#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncidentReason {
    AuthenticationFailure,
    IntegrityViolation,
    QuorumLoss,
    RestoreFailure,
    LivenessFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum IncidentSeverity {
    Advisory,
    Elevated,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationScope {
    LocalOperator,
    RecoveryTeam,
    SecurityLeadership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EscalationReport {
    pub reason: IncidentReason,
    pub signal_count: u32,
    pub severity: IncidentSeverity,
    pub scope: NotificationScope,
}

pub fn classify(reason: IncidentReason, signal_count: u32) -> EscalationReport {
    let base = match reason {
        IncidentReason::AuthenticationFailure | IncidentReason::LivenessFailure => {
            IncidentSeverity::Advisory
        }
        IncidentReason::QuorumLoss | IncidentReason::RestoreFailure => IncidentSeverity::Elevated,
        IncidentReason::IntegrityViolation => IncidentSeverity::Critical,
    };
    let severity = if signal_count >= 3 {
        IncidentSeverity::Critical
    } else if signal_count >= 2 {
        base.max(IncidentSeverity::Elevated)
    } else {
        base
    };
    let scope = match severity {
        IncidentSeverity::Advisory => NotificationScope::LocalOperator,
        IncidentSeverity::Elevated => NotificationScope::RecoveryTeam,
        IncidentSeverity::Critical => NotificationScope::SecurityLeadership,
    };
    EscalationReport {
        reason,
        signal_count,
        severity,
        scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escalates_from_bounded_semantics_only() {
        assert_eq!(
            classify(IncidentReason::AuthenticationFailure, 1).scope,
            NotificationScope::LocalOperator
        );
        assert_eq!(
            classify(IncidentReason::AuthenticationFailure, 2).scope,
            NotificationScope::RecoveryTeam
        );
        assert_eq!(
            classify(IncidentReason::AuthenticationFailure, 3).scope,
            NotificationScope::SecurityLeadership
        );
    }
    #[test]
    fn integrity_violation_is_immediately_critical() {
        let report = classify(IncidentReason::IntegrityViolation, 1);
        assert_eq!(report.severity, IncidentSeverity::Critical);
        assert_eq!(report.scope, NotificationScope::SecurityLeadership);
    }
}
