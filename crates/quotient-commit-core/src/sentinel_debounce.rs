//! Digest-aware alarm deduplication without suppressing distinct evidence.

use std::collections::BTreeMap;

use crate::sentinel_alarm_fusion::AssuranceAlarm;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlarmDebounce {
    minimum_sequence_gap: u64,
    last_by_digest: BTreeMap<[u8; 32], u64>,
}

impl AlarmDebounce {
    pub fn new(minimum_sequence_gap: u64) -> Option<Self> {
        (minimum_sequence_gap > 0).then_some(Self {
            minimum_sequence_gap,
            last_by_digest: BTreeMap::new(),
        })
    }

    pub fn admit(&mut self, alarm: AssuranceAlarm) -> bool {
        let last = self.last_by_digest.get(&alarm.evidence_digest).copied();
        if last.is_some_and(|sequence| {
            alarm.sequence.saturating_sub(sequence) < self.minimum_sequence_gap
        }) {
            return false;
        }
        self.last_by_digest
            .insert(alarm.evidence_digest, alarm.sequence);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_alarm_fusion::{AlarmKind, AlarmSeverity};

    fn alarm(sequence: u64, digest: u8) -> AssuranceAlarm {
        AssuranceAlarm {
            sequence,
            severity: AlarmSeverity::Elevated,
            kind: AlarmKind::Privacy,
            evidence_digest: [digest; 32],
        }
    }

    #[test]
    fn duplicate_is_suppressed_but_distinct_evidence_survives() {
        let mut debounce = AlarmDebounce::new(3).unwrap();
        assert!(debounce.admit(alarm(10, 1)));
        assert!(!debounce.admit(alarm(11, 1)));
        assert!(debounce.admit(alarm(11, 2)));
    }
}
