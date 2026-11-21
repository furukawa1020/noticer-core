//! Deterministic priority fusion of independent runtime alarms.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AlarmSeverity {
    Notice,
    Elevated,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AlarmKind {
    Novelty,
    Support,
    Privacy,
    Liveness,
    Semantics,
    Safety,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceAlarm {
    pub sequence: u64,
    pub severity: AlarmSeverity,
    pub kind: AlarmKind,
    pub evidence_digest: [u8; 32],
}

pub fn fuse(alarms: &[AssuranceAlarm]) -> Option<AssuranceAlarm> {
    alarms.iter().copied().max_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| right.sequence.cmp(&left.sequence))
            .then_with(|| right.evidence_digest.cmp(&left.evidence_digest))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_safety_alarm_dominates_notice() {
        let notice = AssuranceAlarm {
            sequence: 1,
            severity: AlarmSeverity::Notice,
            kind: AlarmKind::Novelty,
            evidence_digest: [1; 32],
        };
        let critical = AssuranceAlarm {
            sequence: 2,
            severity: AlarmSeverity::Critical,
            kind: AlarmKind::Safety,
            evidence_digest: [2; 32],
        };
        assert_eq!(fuse(&[notice, critical]), Some(critical));
    }
}
