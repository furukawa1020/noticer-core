//! Detects new public distinctions within one permitted action class.

use std::collections::{BTreeMap, BTreeSet};

use crate::sentinel_sample::MonitorSample;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePrivacyMonitor {
    maximum_distinctions: usize,
    states: BTreeMap<u16, BTreeSet<u32>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacyViolation {
    pub sequence: u64,
    pub action_class: u16,
    pub observed_distinctions: usize,
}

impl RuntimePrivacyMonitor {
    pub fn new(maximum_distinctions: usize) -> Option<Self> {
        (maximum_distinctions > 0).then_some(Self {
            maximum_distinctions,
            states: BTreeMap::new(),
        })
    }

    pub fn observe(&mut self, sample: MonitorSample) -> Option<PrivacyViolation> {
        let states = self.states.entry(sample.atom.action_class).or_default();
        states.insert(sample.atom.public_state);
        (states.len() > self.maximum_distinctions).then_some(PrivacyViolation {
            sequence: sample.sequence,
            action_class: sample.atom.action_class,
            observed_distinctions: states.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::{PublicRuntimeEvent, RuntimeObservationAtom};

    fn sample(sequence: u64, state: u32) -> MonitorSample {
        MonitorSample::new(
            sequence,
            sequence * 10,
            RuntimeObservationAtom::new(sequence as u32, PublicRuntimeEvent::Release, 1, state)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn second_state_in_one_action_class_is_detected() {
        let mut monitor = RuntimePrivacyMonitor::new(1).unwrap();
        assert_eq!(monitor.observe(sample(1, 7)), None);
        assert_eq!(
            monitor.observe(sample(2, 8)).unwrap().observed_distinctions,
            2
        );
    }
}
