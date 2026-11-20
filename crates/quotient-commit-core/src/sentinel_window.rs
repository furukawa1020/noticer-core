//! Capacity-bounded monotonic runtime evidence window.

use std::collections::VecDeque;

use crate::sentinel_sample::MonitorSample;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvictedObservation {
    pub sequence: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedObservationWindow {
    capacity: usize,
    samples: VecDeque<MonitorSample>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowError {
    ZeroCapacity,
    SequenceRegression,
    TimestampRegression,
    DuplicateSample,
}

impl BoundedObservationWindow {
    pub fn new(capacity: usize) -> Result<Self, WindowError> {
        if capacity == 0 {
            return Err(WindowError::ZeroCapacity);
        }
        Ok(Self {
            capacity,
            samples: VecDeque::with_capacity(capacity),
        })
    }

    pub fn push(
        &mut self,
        sample: MonitorSample,
    ) -> Result<Option<EvictedObservation>, WindowError> {
        if let Some(last) = self.samples.back() {
            if sample.sequence == last.sequence {
                return Err(WindowError::DuplicateSample);
            }
            if sample.sequence < last.sequence {
                return Err(WindowError::SequenceRegression);
            }
            if sample.monotonic_millis < last.monotonic_millis {
                return Err(WindowError::TimestampRegression);
            }
        }
        let evicted = if self.samples.len() == self.capacity {
            self.samples.pop_front().map(|old| EvictedObservation {
                sequence: old.sequence,
                digest: old.digest(),
            })
        } else {
            None
        };
        self.samples.push_back(sample);
        Ok(evicted)
    }

    #[must_use]
    pub fn samples(&self) -> &VecDeque<MonitorSample> {
        &self.samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::{PublicRuntimeEvent, RuntimeObservationAtom};

    fn sample(sequence: u64) -> MonitorSample {
        MonitorSample::new(
            sequence,
            sequence * 10,
            RuntimeObservationAtom::new(sequence as u32, PublicRuntimeEvent::Release, 1, 0)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn eviction_returns_digest_evidence() {
        let mut window = BoundedObservationWindow::new(1).unwrap();
        assert_eq!(window.push(sample(1)), Ok(None));
        let evicted = window.push(sample(2)).unwrap().unwrap();
        assert_eq!(evicted.sequence, 1);
        assert_ne!(evicted.digest, [0; 32]);
    }

    #[test]
    fn sequence_regression_fails_closed() {
        let mut window = BoundedObservationWindow::new(2).unwrap();
        window.push(sample(2)).unwrap();
        assert_eq!(window.push(sample(1)), Err(WindowError::SequenceRegression));
    }
}
