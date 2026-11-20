//! Runtime binding between observed action classes and certified semantics.

use std::collections::BTreeMap;

use crate::sentinel_sample::MonitorSample;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSemanticsMonitor {
    expected_states: BTreeMap<u16, u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticsMonitorError {
    EmptySemantics,
    UnknownActionClass {
        sequence: u64,
    },
    StateDrift {
        sequence: u64,
        expected: u32,
        observed: u32,
    },
}

impl ActionSemanticsMonitor {
    pub fn new(expected_states: BTreeMap<u16, u32>) -> Result<Self, SemanticsMonitorError> {
        if expected_states.is_empty() {
            return Err(SemanticsMonitorError::EmptySemantics);
        }
        Ok(Self { expected_states })
    }

    pub fn observe(&self, sample: MonitorSample) -> Result<(), SemanticsMonitorError> {
        let Some(expected) = self.expected_states.get(&sample.atom.action_class).copied() else {
            return Err(SemanticsMonitorError::UnknownActionClass {
                sequence: sample.sequence,
            });
        };
        if expected != sample.atom.public_state {
            return Err(SemanticsMonitorError::StateDrift {
                sequence: sample.sequence,
                expected,
                observed: sample.atom.public_state,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::{PublicRuntimeEvent, RuntimeObservationAtom};

    #[test]
    fn state_drift_is_detected_at_its_sequence() {
        let monitor = ActionSemanticsMonitor::new(BTreeMap::from([(1, 7)])).unwrap();
        let sample = MonitorSample::new(
            4,
            40,
            RuntimeObservationAtom::new(1, PublicRuntimeEvent::Release, 1, 8).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            monitor.observe(sample),
            Err(SemanticsMonitorError::StateDrift { sequence: 4, .. })
        ));
    }
}
