//! Runtime detection of deny-all and progress-bound violations.

use crate::sentinel_observation_atom::PublicRuntimeEvent;
use crate::sentinel_sample::MonitorSample;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeLivenessMonitor {
    progress_bound_slots: u32,
    last_release_slot: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessViolation {
    ProgressBoundExceeded {
        current_slot: u32,
        last_release_slot: u32,
    },
    NoReleaseObserved {
        current_slot: u32,
    },
}

impl RuntimeLivenessMonitor {
    pub fn new(progress_bound_slots: u32) -> Option<Self> {
        (progress_bound_slots > 0).then_some(Self {
            progress_bound_slots,
            last_release_slot: None,
        })
    }

    pub fn observe(&mut self, sample: MonitorSample) -> Option<LivenessViolation> {
        if sample.atom.event == PublicRuntimeEvent::Release {
            self.last_release_slot = Some(sample.atom.slot);
            return None;
        }
        match self.last_release_slot {
            Some(slot) if sample.atom.slot.saturating_sub(slot) > self.progress_bound_slots => {
                Some(LivenessViolation::ProgressBoundExceeded {
                    current_slot: sample.atom.slot,
                    last_release_slot: slot,
                })
            }
            None if sample.atom.slot > self.progress_bound_slots => {
                Some(LivenessViolation::NoReleaseObserved {
                    current_slot: sample.atom.slot,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::RuntimeObservationAtom;

    #[test]
    fn deny_all_stream_is_detected() {
        let mut monitor = RuntimeLivenessMonitor::new(3).unwrap();
        let sample = MonitorSample::new(
            1,
            10,
            RuntimeObservationAtom::new(4, PublicRuntimeEvent::Suppress, 1, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(
            monitor.observe(sample),
            Some(LivenessViolation::NoReleaseObserved { current_slot: 4 })
        );
    }
}
