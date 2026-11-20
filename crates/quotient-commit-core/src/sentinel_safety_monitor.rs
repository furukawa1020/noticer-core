//! Detects recurrence of the public failure removed by QuotientRemedy.

use crate::sentinel_sample::MonitorSample;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSafetyMonitor {
    forbidden_action_class: u16,
    forbidden_public_state: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyRecurrence {
    pub sequence: u64,
    pub slot: u32,
}

impl RuntimeSafetyMonitor {
    #[must_use]
    pub const fn new(forbidden_action_class: u16, forbidden_public_state: u32) -> Self {
        Self {
            forbidden_action_class,
            forbidden_public_state,
        }
    }

    #[must_use]
    pub const fn observe(self, sample: MonitorSample) -> Option<SafetyRecurrence> {
        if sample.atom.action_class == self.forbidden_action_class
            && sample.atom.public_state == self.forbidden_public_state
        {
            Some(SafetyRecurrence {
                sequence: sample.sequence,
                slot: sample.atom.slot,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::{PublicRuntimeEvent, RuntimeObservationAtom};

    #[test]
    fn exact_certified_failure_recurrence_is_detected() {
        let monitor = RuntimeSafetyMonitor::new(2, 9);
        let sample = MonitorSample::new(
            7,
            70,
            RuntimeObservationAtom::new(3, PublicRuntimeEvent::Transition, 2, 9).unwrap(),
        )
        .unwrap();
        assert_eq!(
            monitor.observe(sample),
            Some(SafetyRecurrence {
                sequence: 7,
                slot: 3
            })
        );
    }
}
